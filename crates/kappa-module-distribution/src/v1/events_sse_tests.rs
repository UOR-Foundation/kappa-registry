use std::sync::Arc;

use kappa_handler::{
    Delivery, EventStream, Gap, MutationEvent, MutationEventOp, Position, PublicationFeed,
    READ_BATCH, clock_at, committed_ledger,
};
use kappa_store::traits::KappaStore;
use kappa_store::{
    Axis, ClockMs, Kappa, NamespaceRef, StoreError, TagUpdate, VerifiedContent, namespace_ensure,
};
use kappa_store_memory::test_support::test_store;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const START_MS: i64 = 1_700_000_000_000;

fn at(physical_ms: i64) -> ClockMs {
    ClockMs::from_raw(physical_ms << 16)
}

struct Fixture {
    store: Arc<dyn KappaStore>,
    namespace: NamespaceRef,
    feed: PublicationFeed,
    clock_ms: i64,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // The store retains its own scope.
        let store: Arc<dyn KappaStore> = Arc::new(test_store()?.into_store());
        let namespace = namespace_ensure(&*store, "repo", None, None, &clock_at(at(START_MS))?)?;
        Ok(Self {
            store,
            namespace,
            feed: PublicationFeed::new(64, 1),
            clock_ms: START_MS,
        })
    }

    /// Publish one epoch setting `names`, notifying the feed as handler
    /// execution does.
    fn publish(&mut self, names: &[String]) -> TestResult {
        self.clock_ms += 1;
        let mut execution = self
            .store
            .begin_execution(&self.namespace, &clock_at(at(self.clock_ms))?)?;
        for name in names {
            let content = VerifiedContent::compute(Axis::Sha256, name.as_bytes())?;
            execution.blob_put(&content)?;
            execution.tag_put(
                name,
                &TagUpdate::Set {
                    kappa: content.kappa().clone(),
                },
            )?;
        }
        let published = execution.publish()?;
        let count = committed_ledger(&*self.store, &self.namespace, &published.root)?.len();
        self.feed.publish(
            &self.namespace,
            published.epoch_number,
            &published.root,
            count as u64,
        );
        Ok(())
    }

    fn stream(&self, position: Position) -> EventStream {
        EventStream::new(
            Arc::clone(&self.store),
            &self.feed,
            self.namespace.clone(),
            position,
        )
    }

    fn head_root(&self) -> Result<Kappa, StoreError> {
        Ok(self.store.epoch_current(&self.namespace)?.1)
    }
}

fn names(prefix: &str, count: usize) -> Vec<String> {
    (0..count).map(|index| format!("{prefix}{index}")).collect()
}

async fn next_event(stream: &mut EventStream) -> Result<MutationEvent, String> {
    match stream.next().await {
        Delivery::Event(event) => Ok(event),
        Delivery::Gap { gap, after } => Err(format!("gap {} after {}", gap.as_str(), after.id())),
    }
}

/// The SSE frame's type is `kind` and its id is `id`. `Event` exposes its
/// fields only through `Debug`.
fn assert_frame(delivery: &Delivery, kind: &str, id: &str) {
    let (event, ends) = frame(delivery);
    assert!(!ends);
    let rendered = format!("{event:?}");
    assert!(
        rendered.contains(&format!("kind: Some({kind:?})")),
        "{rendered}"
    );
    assert!(
        rendered.contains(&format!("id: Some({id:?})")),
        "{rendered}"
    );
}

fn assert_gap(delivery: &Delivery, reason: &str) {
    let (event, ends) = frame(delivery);
    assert!(ends);
    let rendered = format!("{event:?}");
    assert!(
        rendered.contains("kind: Some(\"resync_required\")"),
        "{rendered}"
    );
    assert!(
        rendered.contains(&format!("\\\"reason\\\":\\\"{reason}\\\"")),
        "{rendered}"
    );
}

#[tokio::test]
async fn history_replays_from_the_first_epoch_in_ledger_order_then_continues_live() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.publish(&names("a", 1))?;
    let mut stream = fixture.stream(Position::start());
    let mut replayed = Vec::new();
    // Epoch 1 created the namespace; epoch 2 published a blob and a tag.
    loop {
        let event = next_event(&mut stream).await?;
        let done = event.name == "a0";
        replayed.push(event);
        if done {
            break;
        }
    }
    for pair in replayed.windows(2) {
        assert!((pair[0].epoch, pair[0].index) < (pair[1].epoch, pair[1].index));
    }
    let last = replayed.last().ok_or("no event replayed")?;
    assert_eq!(last.root, fixture.head_root()?.to_string());
    assert_eq!(stream.position(), &Position::after(last));

    fixture.publish(&names("b", 1))?;
    let live = loop {
        let event = next_event(&mut stream).await?;
        if event.operation == MutationEventOp::TagSet {
            break event;
        }
    };
    assert_eq!(live.name, "b0");
    assert_eq!(live.epoch, last.epoch + 1);
    assert_frame(&Delivery::Event(live.clone()), "tag_set", &live.id());
    Ok(())
}

#[tokio::test]
async fn a_subscriber_without_a_cursor_starts_after_the_head() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.publish(&names("old", 3))?;
    let head = head_position(&*fixture.store, &fixture.namespace)?;
    let head_epoch = head.epoch;
    let mut stream = fixture.stream(head);
    let publish = async {
        tokio::task::yield_now().await;
        fixture.publish(&names("new", 1))
    };
    let (delivered, published) = tokio::join!(next_event(&mut stream), publish);
    published?;
    let delivered = delivered?;
    assert_eq!(
        delivered.epoch,
        head_epoch + 1,
        "no event of the head was replayed"
    );
    assert_eq!(delivered.index, 0);
    Ok(())
}

#[tokio::test]
async fn a_resumed_cursor_continues_inside_its_epoch_without_duplicates() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.publish(&names("t", 4))?;
    let mut first = fixture.stream(Position::start());
    let mut seen = Vec::new();
    while seen.len() < 5 {
        seen.push(next_event(&mut first).await?);
    }
    let resume = Position::parse(&seen[2].id())?;
    let mut resumed = fixture.stream(resume);
    assert_eq!(next_event(&mut resumed).await?, seen[3]);
    assert_eq!(next_event(&mut resumed).await?, seen[4]);
    Ok(())
}

#[tokio::test]
async fn a_filter_advances_across_read_batches_to_the_matching_event() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.publish(&names("excluded/", READ_BATCH))?;
    fixture.publish(&["included/tag".to_string()])?;
    let mut stream = fixture.stream(Position::start());
    stream.set_filter(|event| event.name.starts_with("included/"));
    let matching = next_event(&mut stream).await?;
    assert_eq!(matching.name, "included/tag");
    assert_eq!(stream.position(), &Position::after(&matching));
    Ok(())
}

#[tokio::test]
async fn a_cursor_past_the_head_is_refused_not_awaited() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.publish(&names("a", 1))?;
    let root = fixture.head_root()?;
    let mut stream = fixture.stream(Position {
        epoch: 500,
        consumed: 0,
        root: Some(root.to_string()),
    });
    let delivery = stream.next().await;
    assert!(matches!(
        delivery,
        Delivery::Gap {
            gap: Gap::Ahead,
            ..
        }
    ));
    assert_gap(&delivery, "ahead");
    assert!(stream.stopped());
    Ok(())
}

#[tokio::test]
async fn a_cursor_naming_another_history_is_reported_diverged() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.publish(&names("a", 1))?;
    let mut stream = fixture.stream(Position {
        epoch: 1,
        consumed: 0,
        root: Some(Kappa::sha256(b"another history").to_string()),
    });
    let delivery = stream.next().await;
    assert!(matches!(
        delivery,
        Delivery::Gap {
            gap: Gap::Diverged,
            ..
        }
    ));
    assert_gap(&delivery, "diverged");
    Ok(())
}

#[test]
fn malformed_cursors_are_bad_requests() {
    for value in ["", "1", "1.1", "x.1.sha256:00", "1.1.not-a-kappa"] {
        assert!(parse_cursor(value).is_err(), "accepted {value:?}");
    }
}
