package server

import (
	"testing"

	"p3y/db"
)

func TestShouldNotifyPlannerAfterBenchmarkVerdict(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("bench-verdict-notify", "4 flags", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	es := pg.Exploration(task.ExplorationID)
	intentID, err := es.AddIntent(map[string]any{"summary": "lead solver", "phase": "exploit"}, 8, nil, "seed")
	if err != nil {
		t.Fatal(err)
	}
	if err := es.SetIntentState(intentID, "running"); err != nil {
		t.Fatal(err)
	}

	// Partial stage flag accepted while Lead-Solver is actively running -> do NOT wake Planner mid-flight.
	if shouldNotifyPlannerAfterBenchmarkVerdict(es, true, false, 4) {
		t.Fatal("expected partial stage flag with running worker to suppress noisy planner wakeup")
	}
	// Completed or rejected or single-flag -> must still notify.
	if !shouldNotifyPlannerAfterBenchmarkVerdict(es, true, true, 4) {
		t.Fatal("expected completed verdict to notify planner")
	}
	if !shouldNotifyPlannerAfterBenchmarkVerdict(es, false, false, 4) {
		t.Fatal("expected rejected verdict to notify planner")
	}
	if !shouldNotifyPlannerAfterBenchmarkVerdict(es, true, false, 1) {
		t.Fatal("expected single-flag verdict to notify planner")
	}

	// Once running intent exits (exhausted), partial stage flag must wake Planner so work does not stall.
	if err := es.SetIntentState(intentID, "exhausted"); err != nil {
		t.Fatal(err)
	}
	if !shouldNotifyPlannerAfterBenchmarkVerdict(es, true, false, 4) {
		t.Fatal("expected partial stage flag with no running worker to wake planner")
	}
}
