import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Observable, from, switchMap } from 'rxjs';
import {
  AdminOverview,
  AssignRolesRequest,
  CreateGroupRequest,
  CreateRoleRequest,
  RolesAndGroupsResponse,
  UserRolesResponse,
} from '../models/admin.models';
import { KeycloakFacadeService } from './keycloak-facade.service';

@Injectable({
  providedIn: 'root',
})
export class AdminApiService {
  private readonly apiUrl = 'http://localhost:8081/api';

  constructor(private readonly http: HttpClient, private readonly keycloakFacade: KeycloakFacadeService) {}

  getOverview(): Observable<AdminOverview> {
    return this.authorizedGet<AdminOverview>('/admin/overview');
  }

  getRolesAndGroups(): Observable<RolesAndGroupsResponse> {
    return this.authorizedGet<RolesAndGroupsResponse>('/admin/roles');
  }

  createRole(payload: CreateRoleRequest): Observable<unknown> {
    return this.authorizedPost('/admin/roles', payload);
  }

  createGroup(payload: CreateGroupRequest): Observable<unknown> {
    return this.authorizedPost('/admin/groups', payload);
  }

  assignRolesToGroup(groupId: string, roleNames: string[]): Observable<unknown> {
    const body: AssignRolesRequest = { roleNames };
    return this.authorizedPost(`/admin/groups/${groupId}/roles`, body);
  }

  getUsersRoles(limit = 20): Observable<UserRolesResponse> {
    const params = new HttpParams().set('limit', String(limit));
    return this.authorizedGet<UserRolesResponse>('/admin/users/roles', params);
  }

  private authorizedGet<T>(path: string, params?: HttpParams): Observable<T> {
    return from(this.keycloakFacade.getValidToken()).pipe(
      switchMap((token) =>
        this.http.get<T>(`${this.apiUrl}${path}`, {
          headers: this.buildHeaders(token),
          params,
        }),
      ),
    );
  }

  private authorizedPost<T>(path: string, body: unknown): Observable<T> {
    return from(this.keycloakFacade.getValidToken()).pipe(
      switchMap((token) =>
        this.http.post<T>(`${this.apiUrl}${path}`, body, {
          headers: this.buildHeaders(token),
        }),
      ),
    );
  }

  private buildHeaders(token: string): HttpHeaders {
    return new HttpHeaders({
      Authorization: `Bearer ${token}`,
    });
  }
}
