import { Routes } from '@angular/router';
import { Login } from './auth/login/login';
import { Dashboard } from './features/dashboard/dashboard';
import { authGuard } from './core/guard/auth-guard';

export const routes: Routes = [
    { path: 'auth/login', component: Login },
    { path: '', component: Dashboard, canActivate: [authGuard] }
];
