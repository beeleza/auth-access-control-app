import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/sign-in.dto';
import { Public } from './public.decorator';
import { SignUpDto } from './dto/sign-up.dto';
import { Roles } from './roles.decorator';
import { Role } from 'src/users/enum/role.enum';
import type { Request, Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async signIn(@Body() signInDto: SignInDto, @Res() res: Response) {
    return await this.authService.signIn(signInDto.email, signInDto.password, res);
  }

  @Roles(Role.Admin)
  // @Public()
  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  async signUp(@Body() signUpDto: SignUpDto) {
    return await this.authService.signUp(signUpDto);
  }

  @Post('refresh')
  async refresh(@Req() req: Request, @Res() res: Response) {
    const refreshToken = req.cookies['refresh_token'];
    console.log(refreshToken)
    return await this.authService.refreshTokens(req, res);
  }

  @Post('logout')
  async logout(@Req() req: any, @Res() res: Response) {
    const userId = req.user?.sub;
    return await this.authService.logout(userId, res);
  }
}
