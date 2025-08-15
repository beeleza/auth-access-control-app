import { Injectable } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap } from 'rxjs';

export interface LoginRequest {
  email: string;
  password: string;
}

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private readonly apiURL = environment.apiUrl;

  constructor(private http: HttpClient, private router: Router) {}

  login(loginRequest: LoginRequest): Observable<{ access_token: string }> {
    return this.http
      .post<{ access_token: string }>(`${this.apiURL}/auth/login`, loginRequest, {
        withCredentials: true,
      })
      .pipe(tap((res) => this.saveAccessToken(res.access_token)));
  }

  logout() {
    sessionStorage.removeItem('access_token');
    this.http.post(`${this.apiURL}/auth/logout`, {}, { withCredentials: true }).subscribe({
      next: () => this.router.navigate(['/auth/login']),
      error: () => this.router.navigate(['/auth/login']), // mesmo em erro redireciona
    });
  }

  saveAccessToken(token: string) {
    return sessionStorage.setItem('access_token', token);
  }

  getAccessToken() {
    return sessionStorage.getItem('access_token');
  }
}
