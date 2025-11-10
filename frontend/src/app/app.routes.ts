import { Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { ProfileComponent } from './profile/profile.component';
import { ProtectedComponent } from './protected/protected.component';
import { AdminComponent } from './admin/admin.component';

export const routes: Routes = [
  { path: '', component: HomeComponent },
  { path: 'profile', component: ProfileComponent },
  { path: 'protected', component: ProtectedComponent },
  { path: 'admin', component: AdminComponent },
  { path: '**', redirectTo: '' },
];
