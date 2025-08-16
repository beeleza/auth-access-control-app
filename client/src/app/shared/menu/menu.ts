import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../core/services/auth.service';
import { User } from '../../core/models/User';

@Component({
  selector: 'app-menu',
  imports: [],
  templateUrl: './menu.html',
  styleUrl: './menu.css'
})
export class Menu implements OnInit {
  userData!: User;

  constructor(private authService: AuthService) {}

  ngOnInit(): void {
    this.getUserProfile();
  }

  getUserProfile() {
    return this.authService.getProfile().subscribe((data) => {
      this.userData = data;
    });
  }

  onLogout() {
    this.authService.logout();
  }
}
