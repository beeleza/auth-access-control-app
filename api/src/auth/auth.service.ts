import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async signIn(email: string, password: string, res: Response) {
    const user = await this.usersService.findByEmail(email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const paylod = {
      sub: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    const access_token = await this.jwtService.signAsync(paylod, {
      secret: process.env.JWT_SECRET,
      expiresIn: '15m',
    });

    const newRefreshToken = await this.jwtService.signAsync(paylod, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: '7d',
    });

    await this.usersService.updateRefreshToken(
      user.id,
      await bcrypt.hash(newRefreshToken, 8),
    );

    res.cookie('refresh_token', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({ access_token });
  }

  async signUp(createUserDto: CreateUserDto) {
    const result = await this.usersService.create(createUserDto);
    return result;
  }

  async refreshTokens(req: Request, res: Response) {
    const refreshToken = req.cookies['refresh_token'];
    if (!refreshToken) throw new UnauthorizedException('No refresh token');

    let payload: any;
    try {
      payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const user = await this.usersService.findById(payload.sub);
    if (!user || !user.hashedRefreshToken) {
      throw new UnauthorizedException('Access Denied');
    }

    const isValid = await bcrypt.compare(refreshToken, user.hashedRefreshToken);
    if (!isValid) throw new UnauthorizedException('Access Denied');

    const newPayload = {
      sub: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    const newAccessToken = await this.jwtService.signAsync(newPayload, {
      secret: process.env.JWT_SECRET,
      expiresIn: '15m',
    });

    const newRefreshToken = await this.jwtService.signAsync(newPayload, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: '7d',
    });

    await this.usersService.updateRefreshToken(
      user.id,
      await bcrypt.hash(newRefreshToken, 8),
    );

    res.cookie('refresh_token', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({ access_token: newAccessToken });
  }

  async logout(userId: string, res: Response) {
    await this.usersService.updateRefreshToken(userId, null);

    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    return res.json({ message: 'Logged out successfully' });
  }
}
