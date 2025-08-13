import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/sign-in.dto';
import { Public } from './public.decorator';
import { SignUpDto } from './dto/sign-up.dto';
import { Roles } from './roles.decorator';
import { Role } from 'src/users/enum/role.enum';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Public()
    @HttpCode(HttpStatus.OK)
    @Post('login')
    async signIn(@Body() signInDto: SignInDto) {
        return await this.authService.signIn(signInDto.email, signInDto.password);
    }

    @Roles(Role.Admin)
    // @Public()
    @HttpCode(HttpStatus.CREATED)
    @Post('signup')
    async signUp(@Body() signUpDto: SignUpDto) {
        return await this.authService.signUp(signUpDto);
    }
}
