import { Injectable } from '@angular/core';
import { KeycloakService } from 'keycloak-angular';
import { KeycloakInstance, KeycloakProfile, KeycloakTokenParsed } from 'keycloak-js';
import { BehaviorSubject, Observable, map } from 'rxjs';

export interface UserContext {
  ready: boolean;
  authenticated: boolean;
  username?: string;
  email?: string;
  fullName?: string;
  roles: string[];
  profile?: KeycloakProfile;
  token?: string;
}

type RealmTokenParsed = KeycloakTokenParsed & {
  realm_access?: {
    roles?: string[];
  };
};

@Injectable({
  providedIn: 'root',
})
export class KeycloakFacadeService {
  private readonly stateSubject = new BehaviorSubject<UserContext>({
    ready: false,
    authenticated: false,
    roles: [],
  });

  readonly state$: Observable<UserContext> = this.stateSubject.asObservable();
  readonly isAdmin$: Observable<boolean> = this.state$.pipe(
    map((state) => state.roles.some((role) => role === 'app-admin' || role === 'admin')),
  );

  constructor(private readonly keycloakService: KeycloakService) {
    this.registerEventListeners();
    void this.refreshState();
  }

  get snapshot(): UserContext {
    return this.stateSubject.value;
  }

  async login(): Promise<void> {
    const instance = this.ensureInstance();
    await instance.login({ redirectUri: window.location.origin + '/' });
  }

  async register(): Promise<void> {
    const instance = this.ensureInstance();
    await instance.register({ redirectUri: window.location.origin + '/' });
  }

  async logout(): Promise<void> {
    const instance = this.ensureInstance();
    await instance.logout({ redirectUri: window.location.origin + '/' });
    void this.refreshState();
  }

  async getValidToken(): Promise<string> {
    const instance = this.ensureInstance();
    if (!instance.authenticated) {
      throw new Error('Для выполнения действия войдите в систему');
    }
    await instance.updateToken(30);
    if (!instance.token) {
      throw new Error('Не удалось получить токен Keycloak');
    }
    return instance.token;
  }

  private registerEventListeners(): void {
    this.keycloakService.keycloakEvents$.subscribe(() => {
      void this.refreshState();
    });
  }

  private async refreshState(): Promise<void> {
    let authenticated = false;
    try {
      authenticated = await this.keycloakService.isLoggedIn();
    } catch {
      authenticated = false;
    }

    let profile: KeycloakProfile | undefined;
    let roles: string[] = [];
    let username = '';
    let email = '';
    let fullName = '';
    let token: string | undefined;

    const instance = this.keycloakService.getKeycloakInstance();
    const ready = Boolean(instance);
    const tokenParsed = (instance?.tokenParsed ?? {}) as RealmTokenParsed;

    if (authenticated && instance) {
      try {
        profile = await this.keycloakService.loadUserProfile();
      } catch {
        profile = undefined;
      }

      token = instance.token ?? undefined;
      roles = [...new Set(tokenParsed.realm_access?.roles ?? [])].sort();
      username = profile?.username ?? (tokenParsed as Record<string, unknown>)['preferred_username']?.toString() ?? '';
      email = profile?.email ?? (tokenParsed as Record<string, unknown>)['email']?.toString() ?? '';
      fullName = `${profile?.firstName ?? ''} ${profile?.lastName ?? ''}`.trim();
    }

    this.stateSubject.next({
      ready,
      authenticated,
      username,
      email,
      fullName,
      roles,
      profile,
      token,
    });
  }

  private ensureInstance(): KeycloakInstance {
    const instance = this.keycloakService.getKeycloakInstance();
    if (!instance) {
      throw new Error('Keycloak ещё инициализируется. Попробуйте чуть позже.');
    }
    return instance;
  }
}
