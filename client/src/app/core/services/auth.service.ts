import { Injectable } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpClient, HttpHeaders } from '@angular/common/http';
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
      error: () => this.router.navigate(['/auth/login']),
    });
  }

  validateToken() {
    const token: string | null = this.getAccessToken();

    if (!token) {
      return new Observable((observer) => {
        observer.next({ valid: false, reason: 'no token' });
        observer.complete();
      });
    }

    const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
    return this.http.get(`${this.apiURL}/auth/validate-token`, { headers });
  }

  saveAccessToken(token: string): void {
    return sessionStorage.setItem('access_token', token);
  }

  getAccessToken(): string | null {
    return sessionStorage.getItem('access_token');
  }
}
