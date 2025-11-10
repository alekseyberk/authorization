import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { CommonModule } from '@angular/common';
import { KeycloakFacadeService } from './services/keycloak-facade.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive, CommonModule],
  template: `
    <header class="app-header" *ngIf="state$ | async as state">
      <div class="title-block">
        <p class="subtitle">Понятный центр управления Keycloak на языке пользователя</p>
        <h1>Keycloak Hub: регистрация, авторизация и роли без хаоса</h1>
      </div>

      <div class="user-panel">
        <ng-container *ngIf="state.ready; else waiting">
          <div *ngIf="state.authenticated; else guest">
            <p class="greeting">
              Вы вошли как <strong>{{ state.fullName || state.username }}</strong>
            </p>
            <p class="muted">{{ state.email || 'Email ещё не указан' }}</p>
            <div class="roles" *ngIf="state.roles.length > 0; else noRoles">
              <span class="badge" [class.badge-admin]="role === 'app-admin' || role === 'admin'" *ngFor="let role of state.roles">
                {{ role }}
              </span>
            </div>
            <ng-template #noRoles>
              <div class="muted">Роли будут присвоены администратором.</div>
            </ng-template>
          </div>
          <ng-template #guest>
            <p class="greeting">Вы ещё не авторизованы.</p>
            <p class="muted">Нажмите «Войти» или «Создать аккаунт», чтобы получить доступ к панели.</p>
          </ng-template>
        </ng-container>
        <ng-template #waiting>
          <p class="muted">Ждём, когда Keycloak подготовится...</p>
        </ng-template>
      </div>
    </header>

    <section class="action-panel" *ngIf="state$ | async as state">
      <button class="btn btn-success" (click)="login()" [disabled]="actionInProgress || !state.ready" *ngIf="!state.authenticated">
        {{ actionInProgress ? 'Выполняем...' : 'Войти' }}
      </button>
      <button class="btn btn-primary" (click)="register()" [disabled]="actionInProgress || !state.ready" *ngIf="!state.authenticated">
        Создать аккаунт
      </button>
      <button class="btn btn-danger" (click)="logout()" [disabled]="actionInProgress || !state.ready" *ngIf="state.authenticated">
        Выйти
      </button>

      <span class="status-chip" *ngIf="!state.ready">Keycloak запускается...</span>
      <span class="status-chip success" *ngIf="state.ready && state.authenticated">Сессия активна</span>
      <span class="status-chip info" *ngIf="state.ready && !state.authenticated">Доступ открыт для всех шагов onboarding</span>
    </section>

    <nav class="main-nav">
      <a routerLink="/" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: true }">Главная</a>
      <a routerLink="/profile" routerLinkActive="active">Профиль</a>
      <a routerLink="/protected" routerLinkActive="active">Тест API</a>
      <a routerLink="/admin" routerLinkActive="active" *ngIf="isAdmin$ | async">Администрирование</a>
    </nav>

    <div class="notification error" *ngIf="errorMessage">
      {{ errorMessage }}
    </div>

    <main class="page-shell">
      <router-outlet></router-outlet>
    </main>
  `,
  styles: [
    `
      .app-header {
        display: flex;
        flex-wrap: wrap;
        justify-content: space-between;
        gap: 24px;
        background: linear-gradient(120deg, #303f9f, #1976d2);
        color: #fff;
        padding: 32px 40px;
        border-bottom: 4px solid rgba(255, 255, 255, 0.2);
      }

      .title-block {
        flex: 1;
        min-width: 280px;
      }

      .title-block h1 {
        margin: 8px 0 0;
        font-size: 28px;
        line-height: 1.3;
      }

      .title-block .subtitle {
        margin: 0;
        font-size: 16px;
        opacity: 0.85;
      }

      .user-panel {
        min-width: 260px;
        background: rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 16px 20px;
      }

      .greeting {
        margin: 0;
        font-size: 18px;
        font-weight: 600;
      }

      .muted {
        margin: 4px 0 12px;
        color: rgba(255, 255, 255, 0.8);
        font-size: 14px;
      }

      .roles {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }

      .badge {
        display: inline-flex;
        align-items: center;
        padding: 4px 10px;
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.15);
        font-size: 13px;
        text-transform: none;
        letter-spacing: 0.2px;
      }

      .badge-admin {
        background: #ffb300;
        color: #17263c;
        font-weight: 600;
      }

      .action-panel {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        align-items: center;
        padding: 16px 40px;
        background: #f0f4ff;
        border-bottom: 1px solid #e0e0e0;
      }

      .status-chip {
        padding: 6px 12px;
        border-radius: 999px;
        font-size: 13px;
        background: #ede7f6;
        color: #4527a0;
      }

      .status-chip.success {
        background: #e8f5e9;
        color: #2e7d32;
      }

      .status-chip.info {
        background: #e3f2fd;
        color: #1565c0;
      }

      .main-nav {
        display: flex;
        gap: 12px;
        padding: 12px 40px;
        background: #ffffff;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
      }

      .main-nav a {
        text-decoration: none;
        color: #37474f;
        padding: 8px 14px;
        border-radius: 6px;
        font-weight: 500;
      }

      .main-nav a.active {
        background: #e3f2fd;
        color: #0d47a1;
      }

      .notification {
        margin: 16px 40px;
        padding: 12px 16px;
        border-radius: 8px;
      }

      .notification.error {
        background: #ffebee;
        color: #c62828;
        border: 1px solid #ef9a9a;
      }

      .page-shell {
        padding: 24px 40px 48px;
      }

      @media (max-width: 768px) {
        .app-header,
        .action-panel,
        .main-nav,
        .page-shell {
          padding-left: 20px;
          padding-right: 20px;
        }

        .main-nav {
          flex-wrap: wrap;
        }
      }
    `,
  ],
})
export class AppComponent {
  readonly state$ = this.keycloakFacade.state$;
  readonly isAdmin$ = this.keycloakFacade.isAdmin$;
  actionInProgress = false;
  errorMessage = '';

  constructor(private readonly keycloakFacade: KeycloakFacadeService) {}

  async login(): Promise<void> {
    await this.runWithLoader(() => this.keycloakFacade.login());
  }

  async register(): Promise<void> {
    await this.runWithLoader(() => this.keycloakFacade.register());
  }

  async logout(): Promise<void> {
    await this.runWithLoader(() => this.keycloakFacade.logout());
  }

  private async runWithLoader(action: () => Promise<void>): Promise<void> {
    this.actionInProgress = true;
    this.errorMessage = '';
    try {
      await action();
    } catch (error) {
      this.errorMessage = this.getReadableError(error);
    } finally {
      this.actionInProgress = false;
    }
  }

  private getReadableError(error: unknown): string {
    if (error instanceof Error) {
      return error.message;
    }
    return 'Не удалось выполнить действие. Повторите попытку ещё раз.';
  }
}
