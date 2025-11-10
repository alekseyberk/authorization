import { Component, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Subject, startWith, switchMap, shareReplay } from 'rxjs';
import { AdminApiService } from '../services/admin-api.service';
import {
  AdminOverview,
  RolesAndGroupsResponse,
  UserRolesResponse,
  UserRolesItem,
} from '../models/admin.models';
import { KeycloakFacadeService } from '../services/keycloak-facade.service';

@Component({
  selector: 'app-admin',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  template: `
    <section class="card" *ngIf="!(isAdmin$ | async)">
      <h2>Нет прав доступа</h2>
      <p>Этот раздел доступен только пользователям с ролью <strong>app-admin</strong> (или realm-ролью admin).</p>
      <p>Попросите существующего администратора добавить вас через панель «Создать группу / назначить роли».</p>
    </section>

    <ng-container *ngIf="isAdmin$ | async">
      <section class="card" *ngIf="overview$ | async as overview">
        <h2>Обзор Keycloak</h2>
        <div class="metrics">
          <div class="metric">
            <span class="label">Пользователи</span>
            <strong>{{ overview.metrics.totalUsers }}</strong>
          </div>
          <div class="metric">
            <span class="label">Администраторы</span>
            <strong>{{ overview.metrics.totalAdmins }}</strong>
          </div>
          <div class="metric">
            <span class="label">Группы</span>
            <strong>{{ overview.metrics.totalGroups }}</strong>
          </div>
          <div class="metric">
            <span class="label">Роли</span>
            <strong>{{ overview.metrics.totalRoles }}</strong>
          </div>
        </div>
        <button class="btn btn-secondary" (click)="refreshAll()">Обновить данные</button>
      </section>

      <section class="grid-2" *ngIf="overview$ | async as overviewData">
        <article class="card">
          <h3>Кто зарегистрировался</h3>
          <p class="muted">События Keycloak (REGISTER)</p>
          <ul class="timeline">
            <li *ngFor="let event of overviewData.recentRegistrations">
              <div>
                <strong>{{ event.displayName || event.username }}</strong>
                <span class="muted">{{ event.occurredAt | date: 'dd.MM.yyyy HH:mm' }}</span>
              </div>
              <div class="muted">userId: {{ event.userId || '—' }}</div>
            </li>
          </ul>
        </article>

        <article class="card">
          <h3>Кто вошёл и с какими ролями</h3>
          <p class="muted">События Keycloak (LOGIN)</p>
          <ul class="timeline">
            <li *ngFor="let event of overviewData.recentLogins">
              <div>
                <strong>{{ event.displayName || event.username }}</strong>
                <span class="muted">{{ event.occurredAt | date: 'dd.MM.yyyy HH:mm' }}</span>
              </div>
              <div class="chips">
                <span class="chip" *ngFor="let role of event.roles">{{ role }}</span>
              </div>
            </li>
          </ul>
        </article>
      </section>

      <section class="card" *ngIf="overview$ | async as overviewStats">
        <h3>Активные сессии</h3>
        <div class="session-list" *ngIf="overviewStats.activeSessions.length; else noSessions">
          <div class="session" *ngFor="let session of overviewStats.activeSessions">
            <div>
              <strong>{{ session.username }}</strong>
              <span class="muted">IP: {{ session.ip || '—' }}</span>
            </div>
            <div class="muted">Последний доступ: {{ session.lastAccess | date: 'dd.MM.yyyy HH:mm' }}</div>
            <div class="chips">
              <span class="chip" *ngFor="let role of session.roles">{{ role }}</span>
            </div>
          </div>
        </div>
        <ng-template #noSessions>
          <p class="muted">Пока нет активных пользовательских сессий.</p>
        </ng-template>
      </section>

      <section class="grid-3" *ngIf="rolesAndGroups$ | async as rg">
        <article class="card form-card">
          <h3>Создать роль</h3>
          <form [formGroup]="roleForm" (ngSubmit)="submitRoleForm()">
            <label>Системное имя роли</label>
            <input formControlName="name" placeholder="Например: app-manager" />

            <label>Описание</label>
            <textarea formControlName="description" rows="2" placeholder="Для чего нужна роль"></textarea>

            <label class="checkbox">
              <input type="checkbox" formControlName="composite" />
              Составная роль
            </label>

            <button class="btn btn-primary" type="submit" [disabled]="roleForm.invalid || roleFormPending">
              {{ roleFormPending ? 'Создаём...' : 'Создать роль' }}
            </button>
          </form>
        </article>

        <article class="card form-card">
          <h3>Создать группу</h3>
          <form [formGroup]="groupForm" (ngSubmit)="submitGroupForm()">
            <label>Название группы</label>
            <input formControlName="name" placeholder="Например: бухгалтерия" />

            <label>Роли (через запятую)</label>
            <textarea formControlName="roleNames" rows="2" placeholder="role-a, role-b"></textarea>

            <button class="btn btn-primary" type="submit" [disabled]="groupForm.invalid || groupFormPending">
              {{ groupFormPending ? 'Создаём...' : 'Создать группу' }}
            </button>
          </form>
        </article>

        <article class="card form-card">
          <h3>Назначить роли группе</h3>
          <form [formGroup]="assignForm" (ngSubmit)="submitAssignForm()">
            <label>Группа</label>
            <select formControlName="groupId">
              <option value="">Выберите группу</option>
              <option *ngFor="let group of rg.groups" [value]="group.id">{{ group.name }}</option>
            </select>

            <label>Список ролей</label>
            <textarea formControlName="roleNames" rows="2" placeholder="role-a, role-b"></textarea>

            <button class="btn btn-primary" type="submit" [disabled]="assignForm.invalid || assignFormPending">
              {{ assignFormPending ? 'Назначаем...' : 'Назначить роли' }}
            </button>
          </form>
        </article>
      </section>

      <section class="card" *ngIf="rolesAndGroups$ | async as rgData">
        <h3>Роли и группы</h3>
        <div class="grid-2">
          <div>
            <h4>Роли ({{ rgData.roles.length }})</h4>
            <ul class="list">
              <li *ngFor="let role of rgData.roles">
                <strong>{{ role.name }}</strong>
                <span class="muted">{{ role.description || 'нет описания' }}</span>
              </li>
            </ul>
          </div>
          <div>
            <h4>Группы ({{ rgData.groups.length }})</h4>
            <ul class="list">
              <li *ngFor="let group of rgData.groups">
                <strong>{{ group.name }}</strong>
                <div class="muted">{{ group.path }}</div>
                <div class="chips">
                  <span class="chip" *ngFor="let role of group.roles">{{ role }}</span>
                  <span class="muted" *ngIf="!group.roles.length">роль не назначена</span>
                </div>
              </li>
            </ul>
          </div>
        </div>
      </section>

      <section class="card" *ngIf="users$ | async as usersData">
        <div class="table-head">
          <h3>Кто и какие роли имеет</h3>
          <label>
            Показывать последних
            <select [value]="currentUsersLimit" (change)="changeUsersLimitFromEvent($event)">
              <option *ngFor="let option of userLimitOptions" [value]="option">{{ option }}</option>
            </select>
            пользователей
          </label>
        </div>
        <div class="table">
          <div class="table-row table-headings">
            <span>Пользователь</span>
            <span>Роли</span>
            <span>Группы</span>
            <span>Создан</span>
          </div>
          <div class="table-row" *ngFor="let user of usersData.users">
            <span>
              <strong>{{ user.username }}</strong>
              <div class="muted">{{ user.email || 'без email' }}</div>
            </span>
            <span>
              <div class="chips">
                <span class="chip" *ngFor="let role of user.roles">{{ role }}</span>
                <span class="muted" *ngIf="!user.roles.length">—</span>
              </div>
            </span>
            <span>
              <div class="chips">
                <span class="chip chip-outline" *ngFor="let group of user.groups">{{ group.name }}</span>
                <span class="muted" *ngIf="!user.groups.length">—</span>
              </div>
            </span>
            <span>{{ user.createdAt ? (user.createdAt | date: 'dd.MM.yyyy HH:mm') : '—' }}</span>
          </div>
        </div>
      </section>

      <div class="notification success" *ngIf="successMessage">
        {{ successMessage }}
      </div>
      <div class="notification error" *ngIf="errorMessage">
        {{ errorMessage }}
      </div>
    </ng-container>
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

      .metrics {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
        gap: 16px;
        margin: 16px 0;
      }

      .metric {
        background: #f3f6ff;
        padding: 16px;
        border-radius: 10px;
        text-align: center;
      }

      .metric .label {
        display: block;
        color: #607d8b;
        margin-bottom: 6px;
      }

      .metric strong {
        font-size: 24px;
        color: #0d47a1;
      }

      .grid-2,
      .grid-3 {
        display: grid;
        gap: 16px;
      }

      .grid-2 {
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      }

      .grid-3 {
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      }

      .timeline {
        list-style: none;
        padding: 0;
        margin: 0;
        display: flex;
        flex-direction: column;
        gap: 12px;
      }

      .chips {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
      }

      .chip {
        padding: 3px 10px;
        border-radius: 12px;
        background: #eceff1;
        font-size: 12px;
      }

      .chip-outline {
        border: 1px dashed #90a4ae;
        background: transparent;
      }

      .session-list {
        display: flex;
        flex-direction: column;
        gap: 12px;
      }

      .session {
        padding: 12px;
        border-radius: 10px;
        background: #f9fbe7;
        border: 1px solid #e6ee9c;
      }

      form {
        display: flex;
        flex-direction: column;
        gap: 10px;
      }

      input,
      textarea,
      select {
        padding: 8px 10px;
        border: 1px solid #cfd8dc;
        border-radius: 8px;
        font-size: 14px;
      }

      .checkbox {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 14px;
      }

      .list {
        list-style: none;
        padding: 0;
        margin: 0;
        display: flex;
        flex-direction: column;
        gap: 10px;
      }

      .table {
        margin-top: 16px;
        border: 1px solid #eceff1;
        border-radius: 10px;
        overflow: hidden;
      }

      .table-row {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 12px;
        padding: 12px;
        border-bottom: 1px solid #eceff1;
      }

      .table-row:last-child {
        border-bottom: none;
      }

      .table-headings {
        background: #f0f4ff;
        font-weight: 600;
      }

      .table-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 12px;
      }

      .notification {
        padding: 12px 16px;
        border-radius: 10px;
        margin-bottom: 16px;
      }

      .notification.success {
        background: #e8f5e9;
        color: #2e7d32;
      }

      .notification.error {
        background: #ffebee;
        color: #c62828;
      }
    `,
  ],
})
export class AdminComponent implements OnDestroy {
  readonly isAdmin$ = this.keycloakFacade.isAdmin$;
  readonly userLimitOptions = [5, 10, 20, 50];
  currentUsersLimit = 10;

  private readonly refreshOverview$ = new Subject<void>();
  private readonly refreshRoles$ = new Subject<void>();
  private readonly refreshUsers$ = new Subject<number>();

  overview$ = this.refreshOverview$.pipe(
    startWith(void 0),
    switchMap(() => this.adminApi.getOverview()),
    shareReplay(1),
  );

  rolesAndGroups$ = this.refreshRoles$.pipe(
    startWith(void 0),
    switchMap(() => this.adminApi.getRolesAndGroups()),
    shareReplay(1),
  );

  users$ = this.refreshUsers$.pipe(
    startWith(this.currentUsersLimit),
    switchMap((limit) => this.adminApi.getUsersRoles(limit)),
    shareReplay(1),
  );

  roleForm = this.fb.group({
    name: ['', Validators.required],
    description: [''],
    composite: [false],
  });

  groupForm = this.fb.group({
    name: ['', Validators.required],
    roleNames: [''],
  });

  assignForm = this.fb.group({
    groupId: ['', Validators.required],
    roleNames: ['', Validators.required],
  });

  roleFormPending = false;
  groupFormPending = false;
  assignFormPending = false;
  successMessage = '';
  errorMessage = '';
  constructor(
    private readonly adminApi: AdminApiService,
    private readonly fb: FormBuilder,
    private readonly keycloakFacade: KeycloakFacadeService,
  ) {}

  ngOnDestroy(): void {
    this.refreshOverview$.complete();
    this.refreshRoles$.complete();
    this.refreshUsers$.complete();
  }

  refreshAll(): void {
    this.refreshOverview$.next();
    this.refreshRoles$.next();
    this.refreshUsers$.next(this.currentUsersLimit);
  }

  changeUsersLimit(value: string): void {
    const parsed = Number(value) || this.currentUsersLimit;
    this.currentUsersLimit = parsed;
    this.refreshUsers$.next(this.currentUsersLimit);
  }

  changeUsersLimitFromEvent(event: Event): void {
    const target = event.target as HTMLSelectElement | null;
    this.changeUsersLimit(target?.value ?? String(this.currentUsersLimit));
  }

  submitRoleForm(): void {
    if (this.roleForm.invalid) {
      return;
    }
    this.resetMessages();
    this.roleFormPending = true;
    const payload = {
      name: this.roleForm.value.name ?? '',
      description: this.roleForm.value.description ?? undefined,
      composite: this.roleForm.value.composite ?? false,
    };
    this.adminApi.createRole(payload).subscribe({
      next: () => {
        this.roleFormPending = false;
        this.successMessage = 'Роль успешно создана';
        this.roleForm.reset({ name: '', description: '', composite: false });
        this.refreshRoles$.next();
      },
      error: (error) => {
        this.roleFormPending = false;
        this.errorMessage = this.getReadableError(error);
      },
    });
  }

  submitGroupForm(): void {
    if (this.groupForm.invalid) {
      return;
    }
    this.resetMessages();
    this.groupFormPending = true;
    const payload = {
      name: this.groupForm.value.name ?? '',
      roleNames: this.extractRoleNames(this.groupForm.value.roleNames ?? ''),
    };
    this.adminApi.createGroup(payload).subscribe({
      next: () => {
        this.groupFormPending = false;
        this.successMessage = 'Группа создана';
        this.groupForm.reset({ name: '', roleNames: '' });
        this.refreshRoles$.next();
      },
      error: (error) => {
        this.groupFormPending = false;
        this.errorMessage = this.getReadableError(error);
      },
    });
  }

  submitAssignForm(): void {
    if (this.assignForm.invalid) {
      return;
    }
    this.resetMessages();
    this.assignFormPending = true;
    const groupId = this.assignForm.value.groupId ?? '';
    const roles = this.extractRoleNames(this.assignForm.value.roleNames ?? '');
    this.adminApi.assignRolesToGroup(groupId, roles).subscribe({
      next: () => {
        this.assignFormPending = false;
        this.successMessage = 'Роли успешно назначены группе';
        this.assignForm.reset({ groupId: '', roleNames: '' });
        this.refreshRoles$.next();
      },
      error: (error) => {
        this.assignFormPending = false;
        this.errorMessage = this.getReadableError(error);
      },
    });
  }

  private extractRoleNames(value: string): string[] {
    return value
      .split(',')
      .map((name) => name.trim())
      .filter((name) => name.length > 0);
  }

  private resetMessages(): void {
    this.successMessage = '';
    this.errorMessage = '';
  }

  private getReadableError(error: unknown): string {
    if (error instanceof Error) {
      return error.message;
    }
    if (typeof error === 'object' && error !== null && 'message' in error) {
      return String((error as { message: string }).message);
    }
    return 'Произошла ошибка при обращении к backend.';
  }
}
