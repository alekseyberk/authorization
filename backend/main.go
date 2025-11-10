package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type Server struct {
	keycloakClient *gocloak.GoCloak
	realm          string
	clientID       string
	clientSecret   string

	adminUser     string
	adminPassword string
}

type UserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

type contextKey string

const (
	ctxUserInfoKey contextKey = "kcUserInfo"
	ctxTokenKey    contextKey = "kcToken"
)

type adminMetrics struct {
	TotalUsers  int `json:"totalUsers"`
	TotalAdmins int `json:"totalAdmins"`
	TotalGroups int `json:"totalGroups"`
	TotalRoles  int `json:"totalRoles"`
}

type adminEventResponse struct {
	UserID      string   `json:"userId"`
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	Event       string   `json:"event"`
	OccurredAt  string   `json:"occurredAt"`
	Roles       []string `json:"roles,omitempty"`
}

type adminSessionResponse struct {
	SessionID  string   `json:"sessionId"`
	UserID     string   `json:"userId"`
	Username   string   `json:"username"`
	Client     string   `json:"client"`
	IP         string   `json:"ip"`
	LastAccess string   `json:"lastAccess"`
	Roles      []string `json:"roles"`
}

type adminOverviewResponse struct {
	Metrics             adminMetrics           `json:"metrics"`
	RecentRegistrations []adminEventResponse   `json:"recentRegistrations"`
	RecentLogins        []adminEventResponse   `json:"recentLogins"`
	ActiveSessions      []adminSessionResponse `json:"activeSessions"`
}

type roleView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Composite   bool   `json:"composite"`
	ClientRole  bool   `json:"clientRole"`
}

type groupView struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Path  string   `json:"path"`
	Roles []string `json:"roles"`
}

type rolesAndGroupsResponse struct {
	Roles  []roleView  `json:"roles"`
	Groups []groupView `json:"groups"`
}

type createRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Composite   bool   `json:"composite"`
}

type createGroupRequest struct {
	Name      string   `json:"name"`
	RoleNames []string `json:"roleNames"`
}

type assignRolesRequest struct {
	RoleNames []string `json:"roleNames"`
}

type namedGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

type userRolesItem struct {
	ID        string       `json:"id"`
	Username  string       `json:"username"`
	Email     string       `json:"email"`
	Roles     []string     `json:"roles"`
	Groups    []namedGroup `json:"groups"`
	CreatedAt string       `json:"createdAt"`
}

type userRolesResponse struct {
	Users []userRolesItem `json:"users"`
}

var adminRoleCandidates = []string{"app-admin", "admin"}

func extractBearerToken(header string) (string, error) {
	if header == "" {
		return "", errors.New("authorization header required")
	}
	value := strings.TrimSpace(header)
	if len(value) > 7 && strings.EqualFold(value[:7], "Bearer ") {
		value = strings.TrimSpace(value[7:])
	}
	if value == "" {
		return "", errors.New("bearer token is empty")
	}
	return value, nil
}

func safeString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func safeInt64(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func formatMillis(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

func formatMillisPtr(value *int64) string {
	if value == nil {
		return ""
	}
	return formatMillis(*value)
}

func (s *Server) rolesForUser(ctx context.Context, adminToken, userID string) ([]string, error) {
	roles, err := s.keycloakClient.GetRealmRolesByUserID(ctx, adminToken, s.realm, userID)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(roles))
	seen := make(map[string]struct{})
	for _, role := range roles {
		if role == nil || role.Name == nil {
			continue
		}
		name := *role.Name
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func (s *Server) groupsForUser(ctx context.Context, adminToken, userID string) ([]namedGroup, error) {
	groups, err := s.keycloakClient.GetUserGroups(ctx, adminToken, s.realm, userID, gocloak.GetGroupsParams{})
	if err != nil {
		return nil, err
	}
	result := make([]namedGroup, 0, len(groups))
	for _, group := range groups {
		if group == nil || group.ID == nil {
			continue
		}
		result = append(result, namedGroup{
			ID:   safeString(group.ID),
			Name: safeString(group.Name),
			Path: safeString(group.Path),
		})
	}
	return result, nil
}

func composeDisplayName(user *gocloak.User) string {
	if user == nil {
		return ""
	}
	fullName := strings.TrimSpace(strings.TrimSpace(fmt.Sprintf("%s %s", safeString(user.FirstName), safeString(user.LastName))))
	if fullName != "" {
		return fullName
	}
	return safeString(user.Username)
}

func (s *Server) userHasOneOfRoles(ctx context.Context, adminToken, userID string, roleNames []string) (bool, error) {
	roles, err := s.rolesForUser(ctx, adminToken, userID)
	if err != nil {
		return false, err
	}
	target := make(map[string]struct{}, len(roleNames))
	for _, r := range roleNames {
		target[r] = struct{}{}
	}
	for _, r := range roles {
		if _, ok := target[r]; ok {
			return true, nil
		}
	}
	return false, nil
}

func normalizeRoleNames(names []string) []string {
	result := make([]string, 0, len(names))
	seen := make(map[string]struct{})
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func NewServer() *Server {
	keycloakURL := getEnv("KEYCLOAK_URL", "http://localhost:8080")
	realm := getEnv("KEYCLOAK_REALM", "master")
	clientID := getEnv("KEYCLOAK_CLIENT_ID", "go-backend")
	clientSecret := getEnv("KEYCLOAK_CLIENT_SECRET", "your-client-secret")

	adminUser := getEnv("KEYCLOAK_ADMIN", "admin")
	adminPassword := getEnv("KEYCLOAK_ADMIN_PASSWORD", "")

	client := gocloak.NewClient(keycloakURL)

	return &Server{
		keycloakClient: client,
		realm:          realm,
		clientID:       clientID,
		clientSecret:   clientSecret,
		adminUser:      adminUser,
		adminPassword:  adminPassword,
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func (s *Server) validateToken(token string) (*gocloak.UserInfo, error) {
	ctx := context.Background()
	result, err := s.keycloakClient.GetUserInfo(ctx, token, s.realm)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %v", err)
	}
	return result, nil
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := extractBearerToken(r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		userInfo, err := s.validateToken(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ctxTokenKey, token)
		ctx = context.WithValue(ctx, ctxUserInfoKey, userInfo)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (s *Server) adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		value := ctx.Value(ctxUserInfoKey)
		userInfo, ok := value.(*gocloak.UserInfo)
		if !ok || userInfo == nil || userInfo.Sub == nil {
			http.Error(w, "user context missing", http.StatusForbidden)
			return
		}

		adminToken, err := s.adminToken(ctx)
		if err != nil {
			http.Error(w, "failed to verify admin rights", http.StatusInternalServerError)
			return
		}

		hasRole, err := s.userHasOneOfRoles(ctx, adminToken, *userInfo.Sub, adminRoleCandidates)
		if err != nil {
			http.Error(w, "failed to verify admin rights", http.StatusInternalServerError)
			return
		}
		if !hasRole {
			http.Error(w, "admin privileges required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func (s *Server) getUserInfo(w http.ResponseWriter, r *http.Request) {
	value := r.Context().Value(ctxUserInfoKey)
	userInfo, ok := value.(*gocloak.UserInfo)
	if !ok || userInfo == nil {
		http.Error(w, "user info missing", http.StatusInternalServerError)
		return
	}
	if userInfo.Sub == nil {
		http.Error(w, "user id missing", http.StatusInternalServerError)
		return
	}

	response := UserInfo{
		ID:       safeString(userInfo.Sub),
		Username: safeString(userInfo.PreferredUsername),
		Email:    safeString(userInfo.Email),
		Name:     safeString(userInfo.Name),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "This is a protected endpoint!",
		"status":  "success",
	})
}

func (s *Server) publicEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "This is a public endpoint!",
		"status":  "success",
	})
}

// Вспомогательные методы для работы с Keycloak Admin API

func (s *Server) adminToken(ctx context.Context) (string, error) {
	if s.adminUser == "" || s.adminPassword == "" {
		return "", errors.New("KEYCLOAK_ADMIN/KEYCLOAK_ADMIN_PASSWORD not set")
	}
	jwt, err := s.keycloakClient.LoginAdmin(ctx, s.adminUser, s.adminPassword, s.realm)
	if err != nil {
		return "", err
	}
	return jwt.AccessToken, nil
}

func (s *Server) ensureRegistrationEnabled(ctx context.Context) error {
	token, err := s.adminToken(ctx)
	if err != nil {
		return err
	}

	realmRep, err := s.keycloakClient.GetRealm(ctx, token, s.realm)
	if err != nil {
		return err
	}

	if realmRep.RegistrationAllowed == nil || !*realmRep.RegistrationAllowed {
		b := true
		realmRep.RegistrationAllowed = &b
		return s.keycloakClient.UpdateRealm(ctx, token, *realmRep)
	}
	return nil
}

func (s *Server) ensureCSPAllowsSPA(ctx context.Context) error {
	token, err := s.adminToken(ctx)
	if err != nil {
		return err
	}

	realmRep, err := s.keycloakClient.GetRealm(ctx, token, s.realm)
	if err != nil {
		return err
	}

	headers := map[string]string{
		// Разрешаем обрамление нашим SPA в dev-сценарии
		"contentSecurityPolicy": "frame-ancestors 'self' http://localhost:4200",
		// Не заставляем X-Frame-Options запрещать фреймы
		"xFrameOptions": "SAMEORIGIN",
	}
	realmRep.BrowserSecurityHeaders = &headers
	return s.keycloakClient.UpdateRealm(ctx, token, *realmRep)
}

func (s *Server) ensureAppAdminRole(ctx context.Context) error {
	token, err := s.adminToken(ctx)
	if err != nil {
		return err
	}

	_, err = s.keycloakClient.GetRealmRole(ctx, token, s.realm, "app-admin")
	if err == nil {
		return nil
	}
	// создаём роль, если нет
	_, err = s.keycloakClient.CreateRealmRole(ctx, token, s.realm, gocloak.Role{
		Name: gocloak.StringP("app-admin"),
	})
	return err
}

func (s *Server) anyAppAdminExists(ctx context.Context) (bool, error) {
	token, err := s.adminToken(ctx)
	if err != nil {
		return false, err
	}

	// получим пользователей в роли app-admin
	users, err := s.keycloakClient.GetUsersByRoleName(ctx, token, s.realm, "app-admin", gocloak.GetUsersByRoleParams{})
	if err != nil {
		// если роли нет — считаем, что админов пока нет
		return false, nil
	}
	return len(users) > 0, nil
}

func (s *Server) createAppAdmin(ctx context.Context, username, password, email string) (string, error) {
	token, err := s.adminToken(ctx)
	if err != nil {
		return "", err
	}

	// создаём пользователя
	uid, err := s.keycloakClient.CreateUser(ctx, token, s.realm, gocloak.User{
		Username:      gocloak.StringP(username),
		Email:         gocloak.StringP(email),
		Enabled:       gocloak.BoolP(true),
		EmailVerified: gocloak.BoolP(true),
	})
	if err != nil {
		return "", err
	}

	// пароль
	if err := s.keycloakClient.SetPassword(ctx, token, uid, s.realm, password, false); err != nil {
		return "", err
	}

	// роль app-admin
	role, err := s.keycloakClient.GetRealmRole(ctx, token, s.realm, "app-admin")
	if err != nil {
		return "", err
	}

	if err := s.keycloakClient.AddRealmRoleToUser(ctx, token, s.realm, uid, []gocloak.Role{*role}); err != nil {
		return "", err
	}

	return uid, nil
}

// Хендлер bootstrap'а:
func (s *Server) bootstrapAdminHandler(w http.ResponseWriter, r *http.Request) {
	type req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	var body req
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ctx := context.Background()

	// 1) регистрация должна быть включена
	if err := s.ensureRegistrationEnabled(ctx); err != nil {
		http.Error(w, "failed to enable registration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 2) создать роль app-admin (если нет)
	if err := s.ensureAppAdminRole(ctx); err != nil {
		http.Error(w, "failed to ensure app-admin role: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 3) разрешаем создать первого админа только если его ещё нет
	exists, err := s.anyAppAdminExists(ctx)
	if err != nil {
		http.Error(w, "failed to check admins: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "admin already exists", http.StatusConflict)
		return
	}

	uid, err := s.createAppAdmin(ctx, body.Username, body.Password, body.Email)
	if err != nil {
		http.Error(w, "failed to create admin: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "created",
		"user_id": uid,
	})
}

func (s *Server) adminOverviewHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	adminToken, err := s.adminToken(ctx)
	if err != nil {
		http.Error(w, "failed to use admin API", http.StatusInternalServerError)
		return
	}

	metrics, err := s.buildAdminMetrics(ctx, adminToken)
	if err != nil {
		http.Error(w, "failed to collect metrics: "+err.Error(), http.StatusInternalServerError)
		return
	}

	registrations, err := s.fetchEvents(ctx, adminToken, []string{"REGISTER"}, 5, false)
	if err != nil {
		log.Println("warn: failed to fetch registrations:", err)
	}

	logins, err := s.fetchEvents(ctx, adminToken, []string{"LOGIN"}, 5, true)
	if err != nil {
		log.Println("warn: failed to fetch logins:", err)
	}

	sessions, err := s.collectActiveSessions(ctx, adminToken, 5)
	if err != nil {
		log.Println("warn: failed to fetch active sessions:", err)
	}

	response := adminOverviewResponse{
		Metrics:             metrics,
		RecentRegistrations: registrations,
		RecentLogins:        logins,
		ActiveSessions:      sessions,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) buildAdminMetrics(ctx context.Context, adminToken string) (adminMetrics, error) {
	var metrics adminMetrics

	totalUsers, err := s.keycloakClient.GetUserCount(ctx, adminToken, s.realm, gocloak.GetUsersParams{})
	if err != nil {
		return metrics, err
	}
	metrics.TotalUsers = totalUsers

	totalGroups, err := s.keycloakClient.GetGroupsCount(ctx, adminToken, s.realm, gocloak.GetGroupsParams{})
	if err != nil {
		return metrics, err
	}
	metrics.TotalGroups = totalGroups

	roles, err := s.keycloakClient.GetRealmRoles(ctx, adminToken, s.realm, gocloak.GetRoleParams{})
	if err != nil {
		return metrics, err
	}
	metrics.TotalRoles = len(roles)

	admins, err := s.keycloakClient.GetUsersByRoleName(ctx, adminToken, s.realm, "app-admin", gocloak.GetUsersByRoleParams{})
	if err != nil {
		return metrics, err
	}
	metrics.TotalAdmins = len(admins)
	if metrics.TotalAdmins == 0 {
		if fallback, err := s.keycloakClient.GetUsersByRoleName(ctx, adminToken, s.realm, "admin", gocloak.GetUsersByRoleParams{}); err == nil {
			metrics.TotalAdmins = len(fallback)
		}
	}

	return metrics, nil
}

func (s *Server) fetchEvents(ctx context.Context, adminToken string, eventTypes []string, limit int, includeRoles bool) ([]adminEventResponse, error) {
	if limit <= 0 {
		return []adminEventResponse{}, nil
	}

	params := gocloak.GetEventsParams{
		Type: eventTypes,
		Max:  gocloak.Int32P(int32(limit)),
	}

	events, err := s.keycloakClient.GetEvents(ctx, adminToken, s.realm, params)
	if err != nil {
		return nil, err
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Time > events[j].Time
	})
	if len(events) > limit {
		events = events[:limit]
	}

	result := make([]adminEventResponse, 0, len(events))
	for _, event := range events {
		if event == nil {
			continue
		}
		userID := safeString(event.UserID)
		username := ""
		displayName := ""
		var roles []string

		if userID != "" {
			user, err := s.keycloakClient.GetUserByID(ctx, adminToken, s.realm, userID)
			if err == nil {
				username = safeString(user.Username)
				displayName = composeDisplayName(user)
			}
			if includeRoles {
				if r, err := s.rolesForUser(ctx, adminToken, userID); err == nil {
					roles = r
				}
			}
		}

		if username == "" && event.Details != nil {
			if value, ok := event.Details["username"]; ok {
				username = value
			}
			if value, ok := event.Details["email"]; ok && displayName == "" {
				displayName = value
			}
		}

		if displayName == "" {
			displayName = username
		}

		result = append(result, adminEventResponse{
			UserID:      userID,
			Username:    username,
			DisplayName: displayName,
			Event:       strings.ToUpper(safeString(event.Type)),
			OccurredAt:  formatMillis(event.Time),
			Roles:       roles,
		})
	}

	return result, nil
}

func (s *Server) collectActiveSessions(ctx context.Context, adminToken string, limit int) ([]adminSessionResponse, error) {
	if limit <= 0 {
		return []adminSessionResponse{}, nil
	}

	params := gocloak.GetUsersParams{
		Max: gocloak.IntP(limit * 5),
	}

	users, err := s.keycloakClient.GetUsers(ctx, adminToken, s.realm, params)
	if err != nil {
		return nil, err
	}

	sessions := make([]adminSessionResponse, 0, limit)
	for _, user := range users {
		if user == nil || user.ID == nil {
			continue
		}

		userSessions, err := s.keycloakClient.GetUserSessions(ctx, adminToken, s.realm, *user.ID)
		if err != nil || len(userSessions) == 0 {
			continue
		}

		userRoles, err := s.rolesForUser(ctx, adminToken, *user.ID)
		if err != nil {
			userRoles = []string{}
		}

		for _, session := range userSessions {
			if session == nil {
				continue
			}
			client := ""
			if session.Clients != nil {
				for _, label := range *session.Clients {
					client = label
					break
				}
			}

			sessions = append(sessions, adminSessionResponse{
				SessionID:  safeString(session.ID),
				UserID:     safeString(session.UserID),
				Username:   safeString(session.Username),
				Client:     client,
				IP:         safeString(session.IPAddress),
				LastAccess: formatMillisPtr(session.LastAccess),
				Roles:      userRoles,
			})

			if len(sessions) >= limit {
				return sessions, nil
			}
		}
	}

	return sessions, nil
}

func (s *Server) rolesAndGroupsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	adminToken, err := s.adminToken(ctx)
	if err != nil {
		http.Error(w, "failed to use admin API", http.StatusInternalServerError)
		return
	}

	roles, err := s.keycloakClient.GetRealmRoles(ctx, adminToken, s.realm, gocloak.GetRoleParams{})
	if err != nil {
		http.Error(w, "failed to load roles: "+err.Error(), http.StatusInternalServerError)
		return
	}

	roleViews := make([]roleView, 0, len(roles))
	for _, role := range roles {
		if role == nil || role.ID == nil || role.Name == nil {
			continue
		}
		roleViews = append(roleViews, roleView{
			ID:          safeString(role.ID),
			Name:        safeString(role.Name),
			Description: safeString(role.Description),
			Composite:   role.Composite != nil && *role.Composite,
			ClientRole:  role.ClientRole != nil && *role.ClientRole,
		})
	}
	sort.Slice(roleViews, func(i, j int) bool {
		return roleViews[i].Name < roleViews[j].Name
	})

	groupLimit := s.parseLimitParam(r, "groupLimit", 15, 50)
	groupParams := gocloak.GetGroupsParams{
		Max:  gocloak.IntP(groupLimit),
		Full: gocloak.BoolP(true),
	}

	groups, err := s.keycloakClient.GetGroups(ctx, adminToken, s.realm, groupParams)
	if err != nil {
		http.Error(w, "failed to load groups: "+err.Error(), http.StatusInternalServerError)
		return
	}

	groupViews := make([]groupView, 0, len(groups))
	for _, group := range groups {
		if group == nil || group.ID == nil {
			continue
		}

		roleNames := []string{}
		if group.RealmRoles != nil {
			roleNames = append(roleNames, (*group.RealmRoles)...)
		} else {
			roleModels, err := s.keycloakClient.GetRealmRolesByGroupID(ctx, adminToken, s.realm, *group.ID)
			if err == nil {
				for _, rm := range roleModels {
					if rm != nil && rm.Name != nil {
						roleNames = append(roleNames, *rm.Name)
					}
				}
			}
		}
		sort.Strings(roleNames)

		groupViews = append(groupViews, groupView{
			ID:    safeString(group.ID),
			Name:  safeString(group.Name),
			Path:  safeString(group.Path),
			Roles: roleNames,
		})
	}

	sort.Slice(groupViews, func(i, j int) bool {
		return groupViews[i].Name < groupViews[j].Name
	})

	response := rolesAndGroupsResponse{
		Roles:  roleViews,
		Groups: groupViews,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) createRoleHandler(w http.ResponseWriter, r *http.Request) {
	var body createRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Description = strings.TrimSpace(body.Description)

	if body.Name == "" {
		http.Error(w, "role name is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	adminToken, err := s.adminToken(ctx)
	if err != nil {
		http.Error(w, "failed to use admin API", http.StatusInternalServerError)
		return
	}

	payload := gocloak.Role{
		Name:        gocloak.StringP(body.Name),
		Description: gocloak.StringP(body.Description),
		Composite:   gocloak.BoolP(body.Composite),
		ClientRole:  gocloak.BoolP(false),
	}

	if _, err := s.keycloakClient.CreateRealmRole(ctx, adminToken, s.realm, payload); err != nil {
		http.Error(w, "failed to create role: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "created",
		"name":   body.Name,
	})
}

func (s *Server) createGroupHandler(w http.ResponseWriter, r *http.Request) {
	var body createGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		http.Error(w, "group name is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	adminToken, err := s.adminToken(ctx)
	if err != nil {
		http.Error(w, "failed to use admin API", http.StatusInternalServerError)
		return
	}

	groupID, err := s.keycloakClient.CreateGroup(ctx, adminToken, s.realm, gocloak.Group{
		Name: gocloak.StringP(body.Name),
	})
	if err != nil {
		http.Error(w, "failed to create group: "+err.Error(), http.StatusInternalServerError)
		return
	}

	roleNames := normalizeRoleNames(body.RoleNames)
	if len(roleNames) > 0 {
		roles, err := s.resolveRolesByName(ctx, adminToken, roleNames)
		if err != nil {
			http.Error(w, "failed to resolve roles: "+err.Error(), http.StatusBadRequest)
			return
		}

		if len(roles) > 0 {
			if err := s.keycloakClient.AddRealmRoleToGroup(ctx, adminToken, s.realm, groupID, roles); err != nil {
				http.Error(w, "failed to assign roles: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "created",
		"group_id": groupID,
	})
}

func (s *Server) assignRolesToGroupHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupID := vars["groupId"]
	if strings.TrimSpace(groupID) == "" {
		http.Error(w, "groupId is required", http.StatusBadRequest)
		return
	}

	var body assignRolesRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	roleNames := normalizeRoleNames(body.RoleNames)
	if len(roleNames) == 0 {
		http.Error(w, "roleNames array is empty", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	adminToken, err := s.adminToken(ctx)
	if err != nil {
		http.Error(w, "failed to use admin API", http.StatusInternalServerError)
		return
	}

	roles, err := s.resolveRolesByName(ctx, adminToken, roleNames)
	if err != nil {
		http.Error(w, "failed to resolve roles: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.keycloakClient.AddRealmRoleToGroup(ctx, adminToken, s.realm, groupID, roles); err != nil {
		http.Error(w, "failed to assign roles: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "updated",
		"group_id": groupID,
	})
}

func (s *Server) usersRolesHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	adminToken, err := s.adminToken(ctx)
	if err != nil {
		http.Error(w, "failed to use admin API", http.StatusInternalServerError)
		return
	}

	limit := s.parseLimitParam(r, "limit", 20, 100)
	params := gocloak.GetUsersParams{
		Max: gocloak.IntP(limit),
	}

	users, err := s.keycloakClient.GetUsers(ctx, adminToken, s.realm, params)
	if err != nil {
		http.Error(w, "failed to load users: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sort.Slice(users, func(i, j int) bool {
		ui := users[i]
		uj := users[j]
		if ui == nil || uj == nil {
			return i < j
		}
		return safeInt64(ui.CreatedTimestamp) > safeInt64(uj.CreatedTimestamp)
	})

	response := userRolesResponse{
		Users: make([]userRolesItem, 0, len(users)),
	}

	for _, user := range users {
		if user == nil || user.ID == nil {
			continue
		}

		roles, err := s.rolesForUser(ctx, adminToken, *user.ID)
		if err != nil {
			log.Println("warn: failed to load roles for user", safeString(user.Username), err)
			roles = []string{}
		}

		groups, err := s.groupsForUser(ctx, adminToken, *user.ID)
		if err != nil {
			log.Println("warn: failed to load groups for user", safeString(user.Username), err)
			groups = []namedGroup{}
		}

		createdAt := ""
		if created := safeInt64(user.CreatedTimestamp); created > 0 {
			createdAt = formatMillis(created)
		}

		response.Users = append(response.Users, userRolesItem{
			ID:        safeString(user.ID),
			Username:  safeString(user.Username),
			Email:     safeString(user.Email),
			Roles:     roles,
			Groups:    groups,
			CreatedAt: createdAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) resolveRolesByName(ctx context.Context, adminToken string, roleNames []string) ([]gocloak.Role, error) {
	cleanNames := normalizeRoleNames(roleNames)
	result := make([]gocloak.Role, 0, len(cleanNames))
	for _, name := range cleanNames {
		role, err := s.keycloakClient.GetRealmRole(ctx, adminToken, s.realm, name)
		if err != nil {
			return nil, err
		}
		result = append(result, *role)
	}
	return result, nil
}

func (s *Server) parseLimitParam(r *http.Request, key string, defaultValue, maxValue int) int {
	value := defaultValue
	raw := r.URL.Query().Get(key)
	if raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			value = parsed
		}
	}
	if maxValue > 0 && value > maxValue {
		value = maxValue
	}
	return value
}

func (s *Server) setupRoutes() *mux.Router {
	r := mux.NewRouter()

	// CORS middleware
	r.Use(func(next http.Handler) http.Handler {
		return handlers.CORS(
			handlers.AllowedOrigins([]string{"http://localhost:4200"}),
			handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
			handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
		)(next)
	})

	// Public endpoints
	r.HandleFunc("/api/public", s.publicEndpoint).Methods("GET")

	// Bootstrap (публичный только до создания первого админа!)
	r.HandleFunc("/api/bootstrap-admin", s.bootstrapAdminHandler).Methods("POST")

	// Protected endpoints
	r.HandleFunc("/api/user", s.authMiddleware(s.getUserInfo)).Methods("GET")
	r.HandleFunc("/api/protected", s.authMiddleware(s.protectedEndpoint)).Methods("GET")

	admin := r.PathPrefix("/api/admin").Subrouter()
	admin.HandleFunc("/overview", s.authMiddleware(s.adminMiddleware(s.adminOverviewHandler))).Methods("GET")
	admin.HandleFunc("/roles", s.authMiddleware(s.adminMiddleware(s.rolesAndGroupsHandler))).Methods("GET")
	admin.HandleFunc("/roles", s.authMiddleware(s.adminMiddleware(s.createRoleHandler))).Methods("POST")
	admin.HandleFunc("/groups", s.authMiddleware(s.adminMiddleware(s.createGroupHandler))).Methods("POST")
	admin.HandleFunc("/groups/{groupId}/roles", s.authMiddleware(s.adminMiddleware(s.assignRolesToGroupHandler))).Methods("POST")
	admin.HandleFunc("/users/roles", s.authMiddleware(s.adminMiddleware(s.usersRolesHandler))).Methods("GET")

	return r
}

// --- ДОБАВИТЬ: ожидание готовности Keycloak ---
func (s *Server) waitUntilKeycloakReady(ctx context.Context) {
	check := func() bool {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://keycloak:8080/realms/master", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 200
	}

	backoff := time.Second
	for {
		log.Println("Waiting for Keycloak readiness...")
		if check() {
			log.Println("✓ Keycloak is ready")
			return
		}
		time.Sleep(backoff)
		if backoff < 5*time.Second {
			backoff += time.Second
		}
	}
}

// --- ДОБАВИТЬ: создание/обновление клиента angular-frontend ---
func (s *Server) ensureAngularClient(ctx context.Context) error {
	token, err := s.adminToken(ctx)
	if err != nil {
		return err
	}

	params := gocloak.GetClientsParams{ClientID: gocloak.StringP("angular-frontend")}
	clients, err := s.keycloakClient.GetClients(ctx, token, s.realm, params)
	if err != nil {
		return err
	}

	redirects := []string{
		"http://localhost:4200",
		"http://localhost:4200/",
		"http://localhost:4200/*",
	}
	webOrigins := []string{"http://localhost:4200"}

	if len(clients) == 0 {
		// создаём Public OIDC SPA-клиент
		id, err := s.keycloakClient.CreateClient(ctx, token, s.realm, gocloak.Client{
			ClientID:                  gocloak.StringP("angular-frontend"),
			Protocol:                  gocloak.StringP("openid-connect"),
			PublicClient:              gocloak.BoolP(true),
			StandardFlowEnabled:       gocloak.BoolP(true),
			DirectAccessGrantsEnabled: gocloak.BoolP(false),
			RedirectURIs:              &redirects,
			WebOrigins:                &webOrigins,
			RootURL:                   gocloak.StringP("http://localhost:4200"),
			Attributes:                &map[string]string{"pkce.code.challenge.method": "S256"},
		})
		if err != nil {
			return err
		}
		log.Println("✓ Created client angular-frontend with ID:", id)
		return nil
	}

	c := clients[0]
	c.PublicClient = gocloak.BoolP(true)
	c.StandardFlowEnabled = gocloak.BoolP(true)
	c.DirectAccessGrantsEnabled = gocloak.BoolP(false)
	c.RedirectURIs = &redirects
	c.WebOrigins = &webOrigins
	c.RootURL = gocloak.StringP("http://localhost:4200")
	if c.Attributes == nil {
		c.Attributes = &map[string]string{}
	}
	(*c.Attributes)["pkce.code.challenge.method"] = "S256"

	if err := s.keycloakClient.UpdateClient(ctx, token, s.realm, *c); err != nil {
		return err
	}
	log.Println("✓ Updated client angular-frontend")
	return nil
}

// --- ДОБАВИТЬ: единая процедура конфигурации ---
func (s *Server) configureKeycloakOnce(ctx context.Context) error {
	if err := s.ensureRegistrationEnabled(ctx); err != nil {
		return fmt.Errorf("enable registration: %w", err)
	}
	if err := s.ensureAngularClient(ctx); err != nil {
		return fmt.Errorf("ensure angular client: %w", err)
	}
	// Включаем CSP для silent check SSO
	if err := s.ensureCSPAllowsSPA(ctx); err != nil {
		return fmt.Errorf("relax CSP: %w", err)
	}
	return nil
}

func main() {
	server := NewServer()

	ctx := context.Background()
	// 1) ждём пока Keycloak поднимется
	server.waitUntilKeycloakReady(ctx)
	// 2) настраиваем (идемпотентно)
	if err := server.configureKeycloakOnce(ctx); err != nil {
		log.Println("warn: initial Keycloak config failed:", err)
		// страховка: крутиться в фоне и пытаться до успеха
		go func() {
			t := time.NewTicker(5 * time.Second)
			defer t.Stop()
			for range t.C {
				if err := server.configureKeycloakOnce(ctx); err == nil {
					log.Println("✓ Keycloak configured successfully (retry)")
					return
				}
			}
		}()
	} else {
		log.Println("✓ Keycloak configured successfully")
	}

	router := server.setupRoutes()
	port := getEnv("PORT", "8081")
	fmt.Printf("Server starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
