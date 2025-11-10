export interface AdminMetrics {
  totalUsers: number;
  totalAdmins: number;
  totalGroups: number;
  totalRoles: number;
}

export interface AdminEvent {
  userId: string;
  username: string;
  displayName: string;
  event: string;
  occurredAt: string;
  roles?: string[];
}

export interface AdminSession {
  sessionId: string;
  userId: string;
  username: string;
  client: string;
  ip: string;
  lastAccess: string;
  roles: string[];
}

export interface AdminOverview {
  metrics: AdminMetrics;
  recentRegistrations: AdminEvent[];
  recentLogins: AdminEvent[];
  activeSessions: AdminSession[];
}

export interface RoleView {
  id: string;
  name: string;
  description: string;
  composite: boolean;
  clientRole: boolean;
}

export interface GroupView {
  id: string;
  name: string;
  path: string;
  roles: string[];
}

export interface RolesAndGroupsResponse {
  roles: RoleView[];
  groups: GroupView[];
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
  composite?: boolean;
}

export interface CreateGroupRequest {
  name: string;
  roleNames?: string[];
}

export interface AssignRolesRequest {
  roleNames: string[];
}

export interface NamedGroup {
  id: string;
  name: string;
  path: string;
}

export interface UserRolesItem {
  id: string;
  username: string;
  email: string;
  roles: string[];
  groups: NamedGroup[];
  createdAt: string;
}

export interface UserRolesResponse {
  users: UserRolesItem[];
}
