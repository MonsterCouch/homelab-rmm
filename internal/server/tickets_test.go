package server

import (
	"fmt"
	"testing"
)

func TestTicketingCRUD(t *testing.T) {
	_, _, b := newTestServer(t)

	// 1. Create ticket
	newTicket := map[string]any{
		"subject":         "Cannot access shared printer",
		"description":     "The HP LaserJet in accounting is not responding to print jobs.",
		"requester_name":  "Alice Smith",
		"requester_email": "alice@example.com",
		"requester_phone": "555-0199",
		"priority":        "high",
	}

	var created Ticket
	b.mustJSON("POST", "/api/tickets", newTicket, &created)
	if created.ID == 0 || created.Subject != "Cannot access shared printer" {
		t.Fatalf("unexpected created ticket: %+v", created)
	}

	// 2. Add comment
	comment := map[string]any{
		"body":        "Restarted the print spooler service remotely. Can you test now?",
		"is_internal": false,
	}
	var createdComment TicketComment
	b.mustJSON("POST", fmt.Sprintf("/api/tickets/%d/comments", created.ID), comment, &createdComment)
	if createdComment.ID == 0 || createdComment.Author != "admin" {
		t.Errorf("unexpected created comment: %+v", createdComment)
	}

	// 3. Get ticket with comments
	var detail TicketWithComments
	b.mustJSON("GET", fmt.Sprintf("/api/tickets/%d", created.ID), nil, &detail)
	if len(detail.Comments) != 1 || detail.Comments[0].Body != comment["body"] {
		t.Errorf("unexpected ticket detail comments: %+v", detail.Comments)
	}

	// 4. Update ticket status to resolved
	var updated Ticket
	b.mustJSON("PUT", fmt.Sprintf("/api/tickets/%d", created.ID), map[string]string{
		"status": "resolved",
	}, &updated)
	if updated.Status != "resolved" || updated.ResolvedAt == 0 {
		t.Errorf("expected status 'resolved' with resolved_at set, got %+v", updated)
	}

	// 5. List tickets
	var list []Ticket
	b.mustJSON("GET", "/api/tickets?status=resolved", nil, &list)
	if len(list) != 1 {
		t.Errorf("expected 1 resolved ticket, got %d", len(list))
	}
}
