import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { KeycloakFacadeService } from '../services/keycloak-facade.service';

interface BackendUserInfo {
  id: string;
  username: string;
  email: string;
  name: string;
}

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [CommonModule],
  template: `
    <section class="card" *ngIf="state$ | async as state">
      <h2>Профиль Keycloak</h2>
      <div class="grid">
        <div>
          <div class="row"><span>Имя:</span><strong>{{ state.fullName || '—' }}</strong></div>
          <div class="row"><span>Логин:</span><strong>{{ state.username || '—' }}</strong></div>
          <div class="row"><span>Email:</span><strong>{{ state.email || '—' }}</strong></div>
          <div class="row">
            <span>Состояние:</span>
            <strong [class.ok]="state.authenticated">{{ state.authenticated ? 'вошёл в систему' : 'не авторизован' }}</strong>
          </div>
        </div>
        <div>
          <p class="subtitle">Мои роли:</p>
          <div class="chips" *ngIf="state.roles.length; else noRoles">
            <span class="chip" [class.chip-admin]="role === 'app-admin' || role === 'admin'" *ngFor="let role of state.roles">
              {{ role }}
            </span>
          </div>
          <ng-template #noRoles>
            <div class="muted">попросите администратора назначить роль</div>
          </ng-template>
        </div>
      </div>
      <p class="hint">
        Эти данные читаются напрямую из Keycloak. Мы автоматически обновляем их при каждом обновлении токена.
      </p>
    </section>

    <section class="card">
      <h3>Проверка связи с backend (Go + Keycloak)</h3>
      <p>
        Нажмите кнопку ниже, и мы обратимся к защищённому endpoint <code>/api/user</code>. Backend получит ваш токен,
        проверит его и вернёт информацию, которую он «видит» через Keycloak.
      </p>
      <button class="btn btn-primary" (click)="loadBackendUserInfo()" [disabled]="backendLoading">
        {{ backendLoading ? 'Запрашиваем...' : 'Запросить профиль с backend' }}
      </button>
      <div class="muted" *ngIf="!snapshot.authenticated">
        Сначала авторизуйтесь в системе, иначе backend не получит токен.
      </div>

      <div class="backend-card success" *ngIf="backendUser">
        <h4>Backend подтвердил токен</h4>
        <ul>
          <li><strong>ID:</strong> {{ backendUser.id }}</li>
          <li><strong>Имя пользователя:</strong> {{ backendUser.username }}</li>
          <li><strong>Email:</strong> {{ backendUser.email }}</li>
          <li><strong>Полное имя:</strong> {{ backendUser.name }}</li>
        </ul>
      </div>

      <div class="backend-card error" *ngIf="errorMessage">
        {{ errorMessage }}
      </div>
    </section>
  `,
  styles: [
    `
      .card {
        background: #ffffff;
        border-radius: 12px;
        padding: 24px;
        box-shadow: 0 4px 18px rgba(0, 0, 0, 0.08);
        margin-bottom: 24px;
      }

      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 16px;
      }

      .row {
        display: flex;
        justify-content: space-between;
        padding: 6px 0;
        border-bottom: 1px solid #eceff1;
      }

      .row span {
        color: #607d8b;
      }

      .row strong {
        color: #263238;
      }

      .row strong.ok {
        color: #2e7d32;
      }

      .chips {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
      }

      .chip {
        padding: 4px 12px;
        border-radius: 20px;
        background: #eceff1;
        font-size: 13px;
      }

      .chip-admin {
        background: #ffe082;
        color: #4e342e;
        font-weight: 600;
      }

      .subtitle {
        font-weight: 600;
        margin-bottom: 8px;
      }

      .hint {
        margin-top: 16px;
        font-size: 13px;
        color: #607d8b;
      }

      .backend-card {
        margin-top: 16px;
        border-radius: 8px;
        padding: 16px;
      }

      .backend-card.success {
        background: #e8f5e9;
        border: 1px solid #a5d6a7;
      }

      .backend-card.error {
        background: #ffebee;
        border: 1px solid #ef9a9a;
        color: #c62828;
      }

      .muted {
        color: #90a4ae;
        margin-top: 8px;
      }
    `,
  ],
})
export class ProfileComponent {
  readonly state$ = this.keycloakFacade.state$;
  backendUser: BackendUserInfo | null = null;
  backendLoading = false;
  errorMessage = '';

  constructor(private readonly keycloakFacade: KeycloakFacadeService, private readonly http: HttpClient) {}

  get snapshot() {
    return this.keycloakFacade.snapshot;
  }

  async loadBackendUserInfo(): Promise<void> {
    this.errorMessage = '';
    this.backendUser = null;
    this.backendLoading = true;
    try {
      const token = await this.keycloakFacade.getValidToken();
      const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
      this.http.get<BackendUserInfo>('http://localhost:8081/api/user', { headers }).subscribe({
        next: (data) => {
          this.backendUser = data;
          this.backendLoading = false;
        },
        error: (error) => {
          this.backendLoading = false;
          this.errorMessage = `Backend ответил с ошибкой: ${error.message}`;
        },
      });
    } catch (error) {
      this.backendLoading = false;
      this.errorMessage = error instanceof Error ? error.message : 'Не удалось запросить backend.';
    }
  }
}
