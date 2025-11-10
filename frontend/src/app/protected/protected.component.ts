import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { KeycloakFacadeService } from '../services/keycloak-facade.service';

interface ApiResponse {
  message: string;
  status: string;
}

@Component({
  selector: 'app-protected',
  standalone: true,
  imports: [CommonModule],
  template: `
    <section class="card">
      <h2>Тестируем API</h2>
      <p>
        Кнопки ниже показывают разницу между публичным и защищённым endpoint. Первой можно нажимать без авторизации,
        вторая требует действующий токен от Keycloak.
      </p>
      <div class="actions">
        <button class="btn btn-primary" (click)="testPublicEndpoint()" [disabled]="loadingPublic">
          {{ loadingPublic ? 'Запрашиваем...' : 'Публичный endpoint' }}
        </button>
        <button class="btn btn-success" (click)="testProtectedEndpoint()" [disabled]="loadingProtected">
          {{ loadingProtected ? 'Проверяем токен...' : 'Защищённый endpoint' }}
        </button>
      </div>
      <div class="muted" *ngIf="!(state$ | async)?.authenticated">
        Для защищённого запроса нужно войти в систему.
      </div>
    </section>

    <section class="card" *ngIf="publicResponse">
      <h3>Ответ публичного сервиса</h3>
      <pre>{{ publicResponse | json }}</pre>
    </section>

    <section class="card" *ngIf="protectedResponse">
      <h3>Ответ защищённого сервиса</h3>
      <pre>{{ protectedResponse | json }}</pre>
    </section>

    <section class="card error" *ngIf="errorMessage">
      {{ errorMessage }}
    </section>
  `,
  styles: [
    `
      .card {
        background: #ffffff;
        border-radius: 12px;
        padding: 24px;
        box-shadow: 0 4px 18px rgba(0, 0, 0, 0.08);
        margin-bottom: 20px;
      }

      .actions {
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
        margin: 12px 0;
      }

      pre {
        background: #263238;
        color: #fff;
        padding: 12px;
        border-radius: 8px;
        font-size: 14px;
        overflow-x: auto;
      }

      .muted {
        color: #90a4ae;
        font-size: 13px;
      }

      .error {
        border: 1px solid #ef9a9a;
        background: #ffebee;
        color: #c62828;
      }
    `,
  ],
})
export class ProtectedComponent {
  readonly state$ = this.keycloakFacade.state$;
  publicResponse: ApiResponse | null = null;
  protectedResponse: ApiResponse | null = null;
  loadingPublic = false;
  loadingProtected = false;
  errorMessage = '';

  constructor(private readonly http: HttpClient, private readonly keycloakFacade: KeycloakFacadeService) {
    this.testPublicEndpoint();
  }

  testPublicEndpoint(): void {
    this.loadingPublic = true;
    this.errorMessage = '';
    this.http.get<ApiResponse>('http://localhost:8081/api/public').subscribe({
      next: (data) => {
        this.publicResponse = data;
        this.loadingPublic = false;
      },
      error: (error) => {
        this.loadingPublic = false;
        this.errorMessage = `Публичный запрос завершился ошибкой: ${error.message}`;
      },
    });
  }

  async testProtectedEndpoint(): Promise<void> {
    this.loadingProtected = true;
    this.errorMessage = '';
    try {
      const token = await this.keycloakFacade.getValidToken();
      const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
      this.http.get<ApiResponse>('http://localhost:8081/api/protected', { headers }).subscribe({
        next: (data) => {
          this.protectedResponse = data;
          this.loadingProtected = false;
        },
        error: (error) => {
          this.loadingProtected = false;
          this.errorMessage = `Защищённый запрос завершился ошибкой: ${error.message}`;
        },
      });
    } catch (error) {
      this.loadingProtected = false;
      this.errorMessage = error instanceof Error ? error.message : 'Не удалось обновить токен';
    }
  }
}
