package server

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Ticket struct {
	ID                  int64  `json:"id"`
	AgentID             string `json:"agent_id"`
	AgentName           string `json:"agent_name,omitempty"`
	OrgID               string `json:"org_id"`
	SiteID              string `json:"site_id"`
	Subject             string `json:"subject"`
	Description         string `json:"description"`
	RequesterName       string `json:"requester_name"`
	RequesterEmail      string `json:"requester_email"`
	RequesterPhone      string `json:"requester_phone"`
	RequesterDomainUser string `json:"requester_domain_user,omitempty"`
	IsInternal          bool   `json:"is_internal"`
	Source              string `json:"source"`
	Status              string `json:"status"`   // open, in_progress, waiting, resolved, closed
	Priority            string `json:"priority"` // low, normal, high, urgent
	AssignedTo          string `json:"assigned_to"`
	CreatedAt           int64  `json:"created_at"`
	UpdatedAt           int64  `json:"updated_at"`
	ResolvedAt          int64  `json:"resolved_at"`
	CommentsCount       int    `json:"comments_count,omitempty"`
}

type TicketComment struct {
	ID         int64  `json:"id"`
	TicketID   int64  `json:"ticket_id"`
	Author     string `json:"author"`
	IsInternal bool   `json:"is_internal"`
	Body       string `json:"body"`
	CreatedAt  int64  `json:"created_at"`
}

type TicketWithComments struct {
	Ticket
	Comments []TicketComment `json:"comments"`
}

type TicketFilter struct {
	Status              string
	Priority            string
	AgentID             string
	OrgID               string
	AssignedTo          string
	Query               string
	IncludeInternal     bool
	RequesterDomainUser string
}

// ---- DB Operations ----

func (d *DB) ListTicketsFiltered(f TicketFilter) ([]Ticket, error) {
	query := `SELECT t.id, t.agent_id, COALESCE(a.display_name, t.agent_id) as agent_name, t.org_id, t.site_id, t.subject, t.description,
		t.requester_name, t.requester_email, t.requester_phone, COALESCE(t.requester_domain_user, ''), COALESCE(t.is_internal, 0), COALESCE(t.source, 'user'),
		t.status, t.priority, t.assigned_to, t.created_at, t.updated_at, t.resolved_at,
		(SELECT COUNT(*) FROM ticket_comments c WHERE c.ticket_id = t.id) as comments_count
		FROM tickets t LEFT JOIN agents a ON a.id = t.agent_id WHERE 1=1`
	var args []any

	if !f.IncludeInternal {
		query += ` AND (t.is_internal = 0 OR t.is_internal IS NULL)`
	}
	if f.Status != "" && f.Status != "all" {
		query += ` AND t.status = ?`
		args = append(args, f.Status)
	}
	if f.Priority != "" && f.Priority != "all" {
		query += ` AND t.priority = ?`
		args = append(args, f.Priority)
	}
	if f.AgentID != "" {
		query += ` AND t.agent_id = ?`
		args = append(args, f.AgentID)
	}
	if f.OrgID != "" {
		query += ` AND t.org_id = ?`
		args = append(args, f.OrgID)
	}
	if f.AssignedTo != "" {
		query += ` AND t.assigned_to = ?`
		args = append(args, f.AssignedTo)
	}
	if f.RequesterDomainUser != "" {
		query += ` AND (t.requester_domain_user = ? OR t.requester_name = ?)`
		args = append(args, f.RequesterDomainUser, f.RequesterDomainUser)
	}
	if f.Query != "" {
		query += ` AND (t.subject LIKE ? OR t.description LIKE ? OR t.requester_name LIKE ? OR t.requester_email LIKE ?)`
		pattern := "%" + f.Query + "%"
		args = append(args, pattern, pattern, pattern, pattern)
	}
	query += ` ORDER BY t.created_at DESC`

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Ticket{}
	for rows.Next() {
		var t Ticket
		var isInternalInt int
		if err := rows.Scan(&t.ID, &t.AgentID, &t.AgentName, &t.OrgID, &t.SiteID, &t.Subject, &t.Description,
			&t.RequesterName, &t.RequesterEmail, &t.RequesterPhone, &t.RequesterDomainUser, &isInternalInt, &t.Source,
			&t.Status, &t.Priority, &t.AssignedTo,
			&t.CreatedAt, &t.UpdatedAt, &t.ResolvedAt, &t.CommentsCount); err != nil {
			return nil, err
		}
		t.IsInternal = isInternalInt != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *DB) ListTickets(status, priority, agentID, orgID, assignedTo, q string) ([]Ticket, error) {
	return d.ListTicketsFiltered(TicketFilter{
		Status:          status,
		Priority:        priority,
		AgentID:         agentID,
		OrgID:           orgID,
		AssignedTo:      assignedTo,
		Query:           q,
		IncludeInternal: true,
	})
}

func (d *DB) GetTicket(id int64) (*TicketWithComments, error) {
	var t Ticket
	var isInternalInt int
	err := d.QueryRow(`SELECT t.id, t.agent_id, COALESCE(a.display_name, t.agent_id) as agent_name, t.org_id, t.site_id, t.subject, t.description,
		t.requester_name, t.requester_email, t.requester_phone, COALESCE(t.requester_domain_user, ''), COALESCE(t.is_internal, 0), COALESCE(t.source, 'user'),
		t.status, t.priority, t.assigned_to, t.created_at, t.updated_at, t.resolved_at,
		(SELECT COUNT(*) FROM ticket_comments c WHERE c.ticket_id = t.id) as comments_count
		FROM tickets t LEFT JOIN agents a ON a.id = t.agent_id WHERE t.id = ?`, id).
		Scan(&t.ID, &t.AgentID, &t.AgentName, &t.OrgID, &t.SiteID, &t.Subject, &t.Description,
			&t.RequesterName, &t.RequesterEmail, &t.RequesterPhone, &t.RequesterDomainUser, &isInternalInt, &t.Source,
			&t.Status, &t.Priority, &t.AssignedTo,
			&t.CreatedAt, &t.UpdatedAt, &t.ResolvedAt, &t.CommentsCount)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	t.IsInternal = isInternalInt != 0

	// Fetch comments
	rows, err := d.Query(`SELECT id, ticket_id, author, is_internal, body, created_at FROM ticket_comments WHERE ticket_id = ? ORDER BY created_at ASC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	comments := []TicketComment{}
	for rows.Next() {
		var c TicketComment
		var cInternalInt int
		if err := rows.Scan(&c.ID, &c.TicketID, &c.Author, &cInternalInt, &c.Body, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.IsInternal = cInternalInt != 0
		comments = append(comments, c)
	}

	return &TicketWithComments{
		Ticket:   t,
		Comments: comments,
	}, nil
}

func (d *DB) CreateTicket(t *Ticket) (*Ticket, error) {
	now := time.Now().Unix()
	t.CreatedAt = now
	t.UpdatedAt = now
	if t.Status == "" {
		t.Status = "open"
	}
	if t.Priority == "" {
		t.Priority = "normal"
	}
	if t.OrgID == "" {
		t.OrgID = "org_default"
	}
	if t.SiteID == "" {
		t.SiteID = "site_default"
	}
	if t.Source == "" {
		t.Source = "user"
	}

	isInternalInt := 0
	if t.IsInternal {
		isInternalInt = 1
	}

	res, err := d.Exec(`INSERT INTO tickets (agent_id, org_id, site_id, subject, description, requester_name, requester_email, requester_phone, requester_domain_user, is_internal, source, status, priority, assigned_to, created_at, updated_at, resolved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.AgentID, t.OrgID, t.SiteID, t.Subject, t.Description, t.RequesterName, t.RequesterEmail, t.RequesterPhone, t.RequesterDomainUser, isInternalInt, t.Source, t.Status, t.Priority, t.AssignedTo, t.CreatedAt, t.UpdatedAt, t.ResolvedAt)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	t.ID = id
	return t, nil
}

func (d *DB) UpdateTicket(t *Ticket) error {
	t.UpdatedAt = time.Now().Unix()
	if (t.Status == "resolved" || t.Status == "closed") && t.ResolvedAt == 0 {
		t.ResolvedAt = t.UpdatedAt
	} else if t.Status != "resolved" && t.Status != "closed" {
		t.ResolvedAt = 0
	}

	isInternalInt := 0
	if t.IsInternal {
		isInternalInt = 1
	}

	_, err := d.Exec(`UPDATE tickets SET agent_id = ?, org_id = ?, site_id = ?, subject = ?, description = ?, requester_name = ?, requester_email = ?, requester_phone = ?, requester_domain_user = ?, is_internal = ?, source = ?, status = ?, priority = ?, assigned_to = ?, updated_at = ?, resolved_at = ? WHERE id = ?`,
		t.AgentID, t.OrgID, t.SiteID, t.Subject, t.Description, t.RequesterName, t.RequesterEmail, t.RequesterPhone, t.RequesterDomainUser, isInternalInt, t.Source, t.Status, t.Priority, t.AssignedTo, t.UpdatedAt, t.ResolvedAt, t.ID)
	return err
}

func (d *DB) DeleteTicket(id int64) error {
	_, err := d.Exec(`DELETE FROM tickets WHERE id = ?`, id)
	return err
}

func (d *DB) CreateTicketComment(c *TicketComment) (*TicketComment, error) {
	now := time.Now().Unix()
	c.CreatedAt = now
	isInternalInt := 0
	if c.IsInternal {
		isInternalInt = 1
	}

	res, err := d.Exec(`INSERT INTO ticket_comments (ticket_id, author, is_internal, body, created_at) VALUES (?, ?, ?, ?, ?)`,
		c.TicketID, c.Author, isInternalInt, c.Body, c.CreatedAt)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	c.ID = id

	// Update ticket updated_at
	_, _ = d.Exec(`UPDATE tickets SET updated_at = ? WHERE id = ?`, now, c.TicketID)
	return c, nil
}

// ---- HTTP Handlers ----

func (s *Server) handleListTickets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	priority := q.Get("priority")
	agentID := q.Get("agent_id")
	orgID := q.Get("org_id")
	assignedTo := q.Get("assigned_to")
	search := q.Get("q")
	me := userFrom(r.Context())

	if agentID != "" {
		if _, ok := s.getScopedAgent(w, r, agentID); !ok {
			return
		}
	}

	tickets, err := s.db.ListTickets(status, priority, agentID, orgID, assignedTo, search)
	if err != nil {
		fail(w, err)
		return
	}

	if me != nil && !me.IsAdmin() && len(me.OrgScope) > 0 {
		filtered := make([]Ticket, 0, len(tickets))
		for _, t := range tickets {
			if s.canAccessAgent(me, t.OrgID) {
				filtered = append(filtered, t)
			}
		}
		tickets = filtered
	}

	writeJSON(w, 200, tickets)
}

func (s *Server) handleGetTicket(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid ticket id")
		return
	}

	ticket, err := s.db.GetTicket(id)
	if err != nil {
		fail(w, err)
		return
	}

	me := userFrom(r.Context())
	if !s.canAccessAgent(me, ticket.OrgID) {
		writeErr(w, http.StatusNotFound, "ticket not found")
		return
	}

	// Filter out internal comments from read-only viewers
	if me != nil && !me.CanWrite() {
		publicComments := make([]TicketComment, 0, len(ticket.Comments))
		for _, c := range ticket.Comments {
			if !c.IsInternal {
				publicComments = append(publicComments, c)
			}
		}
		ticket.Comments = publicComments
	}

	writeJSON(w, 200, ticket)
}

func (s *Server) handleCreateTicket(w http.ResponseWriter, r *http.Request) {
	var t Ticket
	if err := readJSON(r, &t); err != nil {
		fail(w, err)
		return
	}

	if strings.TrimSpace(t.Subject) == "" || strings.TrimSpace(t.Description) == "" {
		writeErr(w, http.StatusBadRequest, "subject and description are required")
		return
	}
	if strings.TrimSpace(t.RequesterName) == "" {
		u := userFrom(r.Context())
		if u != nil {
			t.RequesterName = u.Username
			t.RequesterEmail = u.Email
		} else {
			t.RequesterName = "Anonymous User"
		}
	}

	me := userFrom(r.Context())

	// Auto-populate or validate org/site if agent_id is provided
	if t.AgentID != "" {
		a, ok := s.getScopedAgent(w, r, t.AgentID)
		if !ok {
			return
		}
		if t.OrgID == "" {
			t.OrgID = a.OrgID
		}
		if t.SiteID == "" {
			t.SiteID = a.SiteID
		}
	}

	if t.OrgID != "" {
		if !s.canAccessAgent(me, t.OrgID) {
			writeErr(w, http.StatusForbidden, "unauthorized organization")
			return
		}
	} else if me != nil && !me.IsAdmin() && len(me.OrgScope) > 0 {
		t.OrgID = me.OrgScope[0]
	}

	created, err := s.db.CreateTicket(&t)
	if err != nil {
		fail(w, err)
		return
	}

	s.audit(r, "ticket.create", fmt.Sprintf("#%d: %s", created.ID, created.Subject), map[string]any{
		"ticket_id": created.ID,
		"agent_id":  created.AgentID,
	})

	writeJSON(w, 201, created)
}

func (s *Server) handleUpdateTicket(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid ticket id")
		return
	}

	existing, err := s.db.GetTicket(id)
	if err != nil {
		fail(w, err)
		return
	}

	me := userFrom(r.Context())
	if !s.canAccessAgent(me, existing.OrgID) {
		writeErr(w, http.StatusNotFound, "ticket not found")
		return
	}

	var update Ticket
	if err := readJSON(r, &update); err != nil {
		fail(w, err)
		return
	}

	update.ID = id
	update.CreatedAt = existing.CreatedAt
	if update.Subject == "" {
		update.Subject = existing.Subject
	}
	if update.Description == "" {
		update.Description = existing.Description
	}
	if update.RequesterName == "" {
		update.RequesterName = existing.RequesterName
	}
	if update.RequesterEmail == "" {
		update.RequesterEmail = existing.RequesterEmail
	}
	if update.RequesterPhone == "" {
		update.RequesterPhone = existing.RequesterPhone
	}
	if update.Status == "" {
		update.Status = existing.Status
	}
	if update.Priority == "" {
		update.Priority = existing.Priority
	}
	if update.OrgID == "" {
		update.OrgID = existing.OrgID
	} else if update.OrgID != existing.OrgID && !s.canAccessAgent(me, update.OrgID) {
		writeErr(w, http.StatusForbidden, "cannot move ticket to unauthorized organization")
		return
	}
	if update.SiteID == "" {
		update.SiteID = existing.SiteID
	}
	if update.AgentID == "" {
		update.AgentID = existing.AgentID
	}
	if update.AssignedTo == "" {
		update.AssignedTo = existing.AssignedTo
	}

	if err := s.db.UpdateTicket(&update); err != nil {
		fail(w, err)
		return
	}

	s.audit(r, "ticket.update", fmt.Sprintf("#%d: %s", update.ID, update.Status), map[string]any{
		"ticket_id": update.ID,
		"status":    update.Status,
	})

	writeJSON(w, 200, update)
}

func (s *Server) handleDeleteTicket(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid ticket id")
		return
	}

	if err := s.db.DeleteTicket(id); err != nil {
		fail(w, err)
		return
	}

	s.audit(r, "ticket.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleAddTicketComment(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid ticket id")
		return
	}

	// Verify ticket exists and user has access
	ticket, err := s.db.GetTicket(id)
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if !s.canAccessAgent(me, ticket.OrgID) {
		writeErr(w, http.StatusNotFound, "ticket not found")
		return
	}

	var c TicketComment
	if err := readJSON(r, &c); err != nil {
		fail(w, err)
		return
	}

	if strings.TrimSpace(c.Body) == "" {
		writeErr(w, http.StatusBadRequest, "comment body cannot be empty")
		return
	}

	c.TicketID = id
	u := userFrom(r.Context())
	if u != nil {
		c.Author = u.Username
	} else if c.Author == "" {
		c.Author = "Technician"
	}

	created, err := s.db.CreateTicketComment(&c)
	if err != nil {
		fail(w, err)
		return
	}

	s.audit(r, "ticket.comment", fmt.Sprintf("Comment on #%d", id), map[string]any{
		"ticket_id": id,
	})

	writeJSON(w, 201, created)
}

func (s *Server) handleAgentTickets(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, agentID); !ok {
		return
	}
	tickets, err := s.db.ListTickets("", "", agentID, "", "", "")
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, tickets)
}
