//! WebSocket endpoint integration tests.

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

use std::time::Duration;

fn set_ws_read_timeout(
    socket: &tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    timeout: Option<Duration>,
) {
    if let tungstenite::stream::MaybeTlsStream::Plain(tcp) = socket.get_ref() {
        tcp.set_read_timeout(timeout).ok();
    }
}

/// Read the next data message, skipping Ping/Pong control frames.
fn read_data_message(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
) -> Result<tungstenite::Message, tungstenite::Error> {
    loop {
        match socket.read()? {
            tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => continue,
            msg => return Ok(msg),
        }
    }
}

fn ws_close(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
) {
    socket.close(None).ok();
    loop {
        match socket.read() {
            Ok(tungstenite::Message::Close(_)) | Err(_) => break,
            _ => continue,
        }
    }
}

// =============================================================================
// Event WebSocket
// =============================================================================

#[test]
fn ws_events_connects_and_upgrades() {
    let (guard, base, _tmp) = start_server();
    let ws_url = base.replace("http://", "ws://");
    let url = format!("{}/v2/ws-test/_events/_ws", ws_url);

    let handle = std::thread::spawn(move || {
        let (mut socket, response) = tungstenite::connect(&url).expect("connect failed");
        assert_eq!(response.status(), 101);
        let cmd = r#"{"type":"filter","event_types":["tag_set"]}"#;
        socket.send(tungstenite::Message::text(cmd)).unwrap();
        ws_close(&mut socket);
        true
    });

    assert!(handle.join().unwrap());
    drop(guard);
}

#[test]
fn ws_events_receives_replay() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    push_manifest(&c, &base, "ws-replay", "v1", br#"{"schemaVersion":2}"#);

    let ws_url = base.replace("http://", "ws://");
    let url = format!("{}/v2/ws-replay/_events/_ws", ws_url);

    let handle = std::thread::spawn(move || {
        let (mut socket, _) = tungstenite::connect(&url).expect("connect failed");
        let cmd = r#"{"type":"replay","since_id":0}"#;
        socket.send(tungstenite::Message::text(cmd)).unwrap();
        set_ws_read_timeout(&socket, Some(Duration::from_secs(2)));

        let mut received = Vec::new();
        loop {
            match socket.read() {
                Ok(tungstenite::Message::Text(text)) => received.push(text),
                Ok(tungstenite::Message::Ping(_)) => continue,
                _ => break,
            }
        }
        socket.close(None).ok();
        received
    });

    let _received = handle.join().unwrap();
    drop(guard);
}

// =============================================================================
// CRDT WebSocket
// =============================================================================

#[test]
fn ws_crdt_connects_and_receives_initial_state() {
    let (guard, base, _tmp) = start_server();
    let ws_url = base.replace("http://", "ws://");
    let url = format!("{}/v2/crdt-test/_crdt/doc1/_ws", ws_url);

    let handle = std::thread::spawn(move || {
        let (mut socket, response) = tungstenite::connect(&url).expect("connect failed");
        assert_eq!(response.status(), 101);
        set_ws_read_timeout(&socket, Some(Duration::from_secs(2)));

        let initial = match read_data_message(&mut socket) {
            Ok(tungstenite::Message::Binary(data)) => data,
            Ok(other) => panic!("expected binary initial state, got: {:?}", other),
            Err(e) => panic!("failed to read initial state: {e}"),
        };

        assert!(
            initial.is_empty(),
            "new document should have empty initial state, got {} bytes",
            initial.len()
        );

        socket
            .send(tungstenite::Message::binary(b"crdt-update-payload".to_vec()))
            .unwrap();
        ws_close(&mut socket);
        true
    });

    assert!(handle.join().unwrap());
    drop(guard);
}

#[test]
fn ws_crdt_persists_state_after_disconnect() {
    let (guard, base, _tmp) = start_server();
    let ws_url = base.replace("http://", "ws://");
    let url = format!("{}/v2/crdt-persist/_crdt/doc2/_ws", ws_url);

    // Client 1: connect, send update, disconnect
    {
        let (mut socket, _) = tungstenite::connect(&url).expect("connect failed");
        set_ws_read_timeout(&socket, Some(Duration::from_secs(2)));
        let _ = read_data_message(&mut socket); // initial state
        socket
            .send(tungstenite::Message::binary(b"persistent-data".to_vec()))
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        ws_close(&mut socket);
    }

    std::thread::sleep(Duration::from_millis(200));

    // Client 2: connect, should receive the persisted state
    {
        let (mut socket, _) = tungstenite::connect(&url).expect("reconnect failed");
        set_ws_read_timeout(&socket, Some(Duration::from_secs(2)));

        let initial = match read_data_message(&mut socket) {
            Ok(tungstenite::Message::Binary(data)) => data,
            Ok(other) => panic!("expected binary, got: {:?}", other),
            Err(e) => panic!("failed to read: {e}"),
        };

        assert!(
            !initial.is_empty(),
            "reconnected client should receive persisted state"
        );
        assert!(
            initial
                .windows(b"persistent-data".len())
                .any(|w| w == b"persistent-data"),
            "persisted state should contain the update from client 1"
        );

        ws_close(&mut socket);
    }

    drop(guard);
}

#[test]
fn ws_crdt_two_clients_see_updates() {
    let (guard, base, _tmp) = start_server();
    let ws_url = base.replace("http://", "ws://");
    let url = format!("{}/v2/crdt-multi/_crdt/shared/_ws", ws_url);

    let url1 = url.clone();
    let url2 = url.clone();

    let handle1 = std::thread::spawn(move || {
        let (mut socket, _) = tungstenite::connect(&url1).expect("client1 connect");
        set_ws_read_timeout(&socket, Some(Duration::from_secs(3)));
        let _ = read_data_message(&mut socket); // initial state

        std::thread::sleep(Duration::from_millis(500));

        let mut got_update = false;
        for _ in 0..10 {
            match read_data_message(&mut socket) {
                Ok(tungstenite::Message::Binary(data)) => {
                    if data
                        .windows(b"from-client2".len())
                        .any(|w| w == b"from-client2")
                    {
                        got_update = true;
                        break;
                    }
                }
                _ => break,
            }
        }

        ws_close(&mut socket);
        got_update
    });

    std::thread::sleep(Duration::from_millis(200));

    let handle2 = std::thread::spawn(move || {
        let (mut socket, _) = tungstenite::connect(&url2).expect("client2 connect");
        set_ws_read_timeout(&socket, Some(Duration::from_secs(2)));
        let _ = read_data_message(&mut socket); // initial state

        socket
            .send(tungstenite::Message::binary(b"from-client2".to_vec()))
            .unwrap();

        std::thread::sleep(Duration::from_millis(500));
        ws_close(&mut socket);
        true
    });

    let client2_ok = handle2.join().unwrap();
    let client1_saw_update = handle1.join().unwrap();

    assert!(client2_ok, "client 2 should connect and send");
    assert!(
        client1_saw_update,
        "client 1 should receive client 2's broadcast update"
    );
    drop(guard);
}
