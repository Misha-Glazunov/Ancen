package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// friendsTestDB opens the test DB and swaps the package-level db for the
// duration of the test, same pattern as user_delete_test.go.
func friendsTestDB(t *testing.T) *sql.DB {
	t.Helper()
	testDB := connectTestDB(t)
	t.Cleanup(func() { testDB.Close() })
	prevDB := db
	db = testDB
	t.Cleanup(func() { db = prevDB })
	return testDB
}

func cleanupFriendship(testDB *sql.DB, a, b int) {
	testDB.Exec("DELETE FROM friendships WHERE (requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)", a, b, b, a)
}

func TestSendFriendRequest_CreatesPending(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)
	b := createTestUser(t, testDB, false)
	var bUsername string
	testDB.QueryRow("SELECT username FROM users WHERE id = ?", b).Scan(&bUsername)
	t.Cleanup(func() { cleanupFriendship(testDB, a, b) })

	status, err := sendFriendRequest(a, bUsername)
	if err != nil {
		t.Fatalf("sendFriendRequest: %v", err)
	}
	if status != "pending_sent" {
		t.Errorf("expected pending_sent, got %q", status)
	}
	if got := getFriendshipStatus(a, b); got != "pending_sent" {
		t.Errorf("requester status: expected pending_sent, got %q", got)
	}
	if got := getFriendshipStatus(b, a); got != "pending_received" {
		t.Errorf("addressee status: expected pending_received, got %q", got)
	}
}

func TestSendFriendRequest_RejectsSelf(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)
	var aUsername string
	testDB.QueryRow("SELECT username FROM users WHERE id = ?", a).Scan(&aUsername)

	if _, err := sendFriendRequest(a, aUsername); err == nil {
		t.Error("expected error when adding self as friend")
	}
}

func TestSendFriendRequest_UnknownUsername(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)

	if _, err := sendFriendRequest(a, "no-such-user-ever"); err == nil {
		t.Error("expected error for nonexistent target username")
	}
}

func TestSendFriendRequest_MutualAutoAccepts(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)
	b := createTestUser(t, testDB, false)
	var aUsername, bUsername string
	testDB.QueryRow("SELECT username FROM users WHERE id = ?", a).Scan(&aUsername)
	testDB.QueryRow("SELECT username FROM users WHERE id = ?", b).Scan(&bUsername)
	t.Cleanup(func() { cleanupFriendship(testDB, a, b) })

	if _, err := sendFriendRequest(a, bUsername); err != nil {
		t.Fatalf("first request: %v", err)
	}
	status, err := sendFriendRequest(b, aUsername)
	if err != nil {
		t.Fatalf("reverse request: %v", err)
	}
	if status != "friends" {
		t.Errorf("expected mutual request to auto-accept to friends, got %q", status)
	}

	// Should not have created a second row — still exactly one accepted pair.
	var count int
	testDB.QueryRow("SELECT COUNT(*) FROM friendships WHERE (requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)", a, b, b, a).Scan(&count)
	if count != 1 {
		t.Errorf("expected exactly 1 friendship row, got %d", count)
	}
}

func TestSendFriendRequest_AlreadyFriendsIsNoop(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)
	b := createTestUser(t, testDB, false)
	var bUsername string
	testDB.QueryRow("SELECT username FROM users WHERE id = ?", b).Scan(&bUsername)
	t.Cleanup(func() { cleanupFriendship(testDB, a, b) })

	testDB.Exec("INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'accepted')", a, b)

	status, err := sendFriendRequest(a, bUsername)
	if err != nil {
		t.Fatalf("sendFriendRequest: %v", err)
	}
	if status != "friends" {
		t.Errorf("expected friends, got %q", status)
	}
}

func TestRespondFriendRequest_Accept(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)
	b := createTestUser(t, testDB, false)
	t.Cleanup(func() { cleanupFriendship(testDB, a, b) })

	res, err := testDB.Exec("INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'pending')", a, b)
	if err != nil {
		t.Fatal(err)
	}
	reqID, _ := res.LastInsertId()

	if err := respondFriendRequest(b, int(reqID), true); err != nil {
		t.Fatalf("respondFriendRequest accept: %v", err)
	}
	if got := getFriendshipStatus(a, b); got != "friends" {
		t.Errorf("expected friends after accept, got %q", got)
	}
}

func TestRespondFriendRequest_Decline(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)
	b := createTestUser(t, testDB, false)
	t.Cleanup(func() { cleanupFriendship(testDB, a, b) })

	res, err := testDB.Exec("INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'pending')", a, b)
	if err != nil {
		t.Fatal(err)
	}
	reqID, _ := res.LastInsertId()

	if err := respondFriendRequest(b, int(reqID), false); err != nil {
		t.Fatalf("respondFriendRequest decline: %v", err)
	}
	if got := getFriendshipStatus(a, b); got != "none" {
		t.Errorf("expected none after decline, got %q", got)
	}
}

func TestRespondFriendRequest_WrongUserCannotRespond(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)
	b := createTestUser(t, testDB, false)
	c := createTestUser(t, testDB, false)
	t.Cleanup(func() { cleanupFriendship(testDB, a, b) })

	res, err := testDB.Exec("INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'pending')", a, b)
	if err != nil {
		t.Fatal(err)
	}
	reqID, _ := res.LastInsertId()

	// c is neither requester nor addressee — must not be able to accept it.
	if err := respondFriendRequest(c, int(reqID), true); err == nil {
		t.Error("expected error when a third party responds to a request not addressed to them")
	}
	if got := getFriendshipStatus(a, b); got != "pending_sent" {
		t.Errorf("request should remain untouched, got %q", got)
	}
}

func TestRemoveFriendship(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)
	b := createTestUser(t, testDB, false)
	t.Cleanup(func() { cleanupFriendship(testDB, a, b) })

	testDB.Exec("INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'accepted')", a, b)

	if err := removeFriendship(a, b); err != nil {
		t.Fatalf("removeFriendship: %v", err)
	}
	if got := getFriendshipStatus(a, b); got != "none" {
		t.Errorf("expected none after remove, got %q", got)
	}
}

func TestGetFriends_ReturnsAcceptedBothDirections(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)
	b := createTestUser(t, testDB, false)
	c := createTestUser(t, testDB, false)
	t.Cleanup(func() {
		cleanupFriendship(testDB, a, b)
		cleanupFriendship(testDB, a, c)
	})

	// a is requester with b, addressee with c — getFriends(a) should include both.
	testDB.Exec("INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'accepted')", a, b)
	testDB.Exec("INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'accepted')", c, a)

	friends := getFriends(a)
	if len(friends) != 2 {
		t.Fatalf("expected 2 friends, got %d", len(friends))
	}
	ids := map[int]bool{friends[0].UserID: true, friends[1].UserID: true}
	if !ids[b] || !ids[c] {
		t.Errorf("expected friends to include both %d and %d, got %+v", b, c, friends)
	}
}

func TestGetPendingIncoming_OnlyAddressee(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)
	b := createTestUser(t, testDB, false)
	t.Cleanup(func() { cleanupFriendship(testDB, a, b) })

	testDB.Exec("INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'pending')", a, b)

	incoming := getPendingIncoming(b)
	if len(incoming) != 1 || incoming[0].UserID != a {
		t.Errorf("expected 1 incoming request from %d, got %+v", a, incoming)
	}
	if incoming := getPendingIncoming(a); len(incoming) != 0 {
		t.Errorf("requester should have no incoming requests, got %+v", incoming)
	}
}

func TestApiFriendRequestPost_Unauthorized(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"username": "someone"})
	req := httptest.NewRequest(http.MethodPost, "/api/friends", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	apiFriendRequestPost(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for anonymous request, got %d", rec.Code)
	}
}

func TestApiFriendRequestPost_Success(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)
	b := createTestUser(t, testDB, false)
	var bUsername string
	testDB.QueryRow("SELECT username FROM users WHERE id = ?", b).Scan(&bUsername)
	t.Cleanup(func() { cleanupFriendship(testDB, a, b) })

	body, _ := json.Marshal(map[string]string{"username": bUsername})
	req := httptest.NewRequest(http.MethodPost, "/api/friends", bytes.NewReader(body))
	req.AddCookie(sessionCookie(t, a))
	rec := httptest.NewRecorder()

	apiFriendRequestPost(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "pending_sent" {
		t.Errorf("expected pending_sent, got %+v", resp)
	}
}

func TestApiFriendRespondPost_AcceptUnlocksAchievement(t *testing.T) {
	testDB := friendsTestDB(t)
	b := createTestUser(t, testDB, false)

	// Give b four existing accepted friendships so the 5th accept crosses the
	// "friendly" achievement threshold (see checkAndUnlockAchievements).
	var others []int
	for i := 0; i < 4; i++ {
		o := createTestUser(t, testDB, false)
		others = append(others, o)
		testDB.Exec("INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'accepted')", o, b)
	}
	a := createTestUser(t, testDB, false)
	t.Cleanup(func() {
		cleanupFriendship(testDB, a, b)
		for _, o := range others {
			cleanupFriendship(testDB, o, b)
		}
		testDB.Exec("DELETE FROM user_achievements WHERE user_id = ?", b)
	})

	res, err := testDB.Exec("INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?, ?, 'pending')", a, b)
	if err != nil {
		t.Fatal(err)
	}
	reqID, _ := res.LastInsertId()

	body, _ := json.Marshal(map[string]interface{}{"request_id": reqID, "action": "accept"})
	req := httptest.NewRequest(http.MethodPost, "/api/friends/respond", bytes.NewReader(body))
	req.AddCookie(sessionCookie(t, b))
	rec := httptest.NewRecorder()

	apiFriendRespondPost(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Status       string        `json:"status"`
		Achievements []Achievement `json:"achievements"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ach := range resp.Achievements {
		if ach.ID == "friendly" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'friendly' achievement to unlock on 5th friend, got %+v", resp.Achievements)
	}
}

func TestProfileByUsernameHandler_OwnProfileRedirects(t *testing.T) {
	testDB := friendsTestDB(t)
	a := createTestUser(t, testDB, false)
	var aUsername string
	testDB.QueryRow("SELECT username FROM users WHERE id = ?", a).Scan(&aUsername)

	req := httptest.NewRequest(http.MethodGet, "/profile/"+aUsername, nil)
	req.AddCookie(sessionCookie(t, a))
	rec := httptest.NewRecorder()

	profileByUsernameHandler(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("expected redirect to canonical /profile, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/profile" {
		t.Errorf("expected redirect to /profile, got %q", loc)
	}
}

func TestProfileByUsernameHandler_UnknownUserIs404(t *testing.T) {
	friendsTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/profile/no-such-user-ever", nil)
	rec := httptest.NewRecorder()

	profileByUsernameHandler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown username, got %d", rec.Code)
	}
}
