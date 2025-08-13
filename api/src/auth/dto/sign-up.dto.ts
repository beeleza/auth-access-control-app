import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class SignUpDto {
  @IsNotEmpty({ message: 'Nome é obrigatório' })
  @IsString()
  name: string;

  @IsNotEmpty({ message: 'E-mail é obrigatório' })
  @IsEmail({}, { message: 'Informe um e-mail válido' })
  email: string;

  @IsNotEmpty({ message: 'Senha é obrigatória' })
  @IsString()
  @MinLength(6, { message: 'Senha deve ter pelo menos 6 caracteres' })
  password: string;
}
