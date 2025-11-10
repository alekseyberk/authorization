import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { KeycloakFacadeService } from '../services/keycloak-facade.service';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule],
  template: `
    <section class="card hero">
      <h2>Добро пожаловать в обёртку Keycloak</h2>
      <p>
        Мы спрятали сложность Keycloak за понятными карточками и действиями. На этой странице вы видите план работ,
        подсказки и статус своей роли. Всё на русском, без лишних терминов.
      </p>
      <ul class="pillars">
        <li><strong>Регистрация</strong>: пара кликов и вы в системе.</li>
        <li><strong>Авторизация</strong>: кнопка «Войти» в шапке всегда под рукой.</li>
        <li><strong>Администратор</strong>: панели для ролей, групп и отслеживания событий.</li>
      </ul>
    </section>

    <section class="grid" *ngIf="state$ | async as state">
      <article class="card steps">
        <h3>Чек-лист пользователя</h3>
        <ol>
          <li>
            <strong>Создайте учётную запись</strong> — кнопка «Создать аккаунт» сверху. После регистрации мы сразу
            покажем вас в списке «Последние регистрации».
          </li>
          <li>
            <strong>Войдите в систему</strong>, чтобы получить доступ к профилю и тестовым API.
            <span class="hint">Мы подсветим, под какой ролью вы вошли.</span>
          </li>
          <li>
            <strong>Попросите администратора</strong> выдать нужную роль или добавить в группу. В панели «Администрирование» есть удобные формы.
          </li>
          <li>
            <strong>Отслеживайте активность</strong>: раздел «Тест API» покажет, что backend принимает токен и знает кто вы.
          </li>
        </ol>
      </article>

      <article class="card status">
        <h3>Ваш статус в системе</h3>
        <div class="status-row">
          <span class="label">Состояние Keycloak:</span>
          <span class="value" [class.ok]="state.ready">{{ state.ready ? 'готов' : 'подготавливается' }}</span>
        </div>
        <div class="status-row">
          <span class="label">Авторизация:</span>
          <span class="value" [class.ok]="state.authenticated">{{ state.authenticated ? 'активна' : 'не выполнена' }}</span>
        </div>
        <div class="status-row">
          <span class="label">Имя пользователя:</span>
          <span class="value">{{ state.fullName || state.username || '—' }}</span>
        </div>
        <div class="status-row">
          <span class="label">Email:</span>
          <span class="value">{{ state.email || '—' }}</span>
        </div>
        <div class="status-row">
          <span class="label">Роли:</span>
          <div class="chips" *ngIf="state.roles.length; else noRoles">
            <span class="chip" [class.chip-admin]="role === 'app-admin' || role === 'admin'" *ngFor="let role of state.roles">
              {{ role }}
            </span>
          </div>
          <ng-template #noRoles>
            <span class="value muted">роль ещё не назначена</span>
          </ng-template>
        </div>
      </article>

      <article class="card admin">
        <h3>Что умеет раздел «Администрирование»</h3>
        <ul>
          <li>Панель метрик: сколько пользователей, групп, ролей и администраторов.</li>
          <li>Ленты «Кто зарегистрировался» и «Кто вошёл» с указанием роли.</li>
          <li>Создание ролей и групп в пару кликов, назначение ролей группам.</li>
          <li>Таблица «Кто и какие роли имеет» с быстрым фильтром по свежим аккаунтам.</li>
          <li>Список активных сессий, чтобы понимать, кто сейчас в системе.</li>
        </ul>
        <p class="hint">
          Если вы состоите в роли <strong>app-admin</strong>, ссылка «Администрирование» появится в верхнем меню автоматически.
        </p>
      </article>
    </section>
  `,
  styles: [
    `
      .hero {
        background: #ffffff;
        border-left: 4px solid #1976d2;
      }

      .pillars {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        list-style: none;
        padding: 0;
        margin: 16px 0 0;
      }

      .pillars li {
        background: #e3f2fd;
        border-radius: 999px;
        padding: 8px 16px;
        font-size: 14px;
      }

      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 16px;
        margin-top: 24px;
      }

      .card {
        background: #ffffff;
        border-radius: 12px;
        padding: 20px 24px;
        box-shadow: 0 6px 20px rgba(15, 22, 36, 0.08);
      }

      .steps ol {
        margin: 0;
        padding-left: 20px;
        display: flex;
        flex-direction: column;
        gap: 8px;
      }

      .hint {
        display: inline-block;
        margin-top: 4px;
        font-size: 13px;
        color: #546e7a;
      }

      .status-row {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-bottom: 12px;
      }

      .label {
        flex: 0 0 150px;
        font-weight: 600;
        color: #37474f;
      }

      .value {
        flex: 1;
        color: #0d47a1;
        font-weight: 500;
      }

      .value.ok {
        color: #2e7d32;
      }

      .value.muted {
        color: #90a4ae;
      }

      .chips {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }

      .chip {
        padding: 4px 10px;
        border-radius: 999px;
        background: #eceff1;
        font-size: 13px;
      }

      .chip-admin {
        background: #ffd54f;
        color: #4e342e;
        font-weight: 600;
      }

      .admin ul {
        padding-left: 20px;
        margin: 12px 0;
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
    `,
  ],
})
export class HomeComponent {
  readonly state$ = this.keycloakFacade.state$;

  constructor(private readonly keycloakFacade: KeycloakFacadeService) {}
}
