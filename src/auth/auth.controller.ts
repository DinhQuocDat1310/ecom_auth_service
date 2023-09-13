import { GoogleAuthGuard } from './guards/google-oauth.guard';
import {
  Controller,
  UseGuards,
  Post,
  Request,
  Get,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { AccessJwtAuthGuard } from './guards/jwt-access-auth.guard';
import {
  Ctx,
  EventPattern,
  MessagePattern,
  Payload,
  RmqContext,
} from '@nestjs/microservices';
import { RabbitMQService } from 'src/libs/common/src';
import { RefreshJwtAuthGuard } from './guards/jwt-refresh-auth.guard';
import { ApiTags, ApiBearerAuth, ApiBody } from '@nestjs/swagger';
import { LoginUserDTO, RequestUser } from './dto/auth';
@Controller('auth')
@ApiTags('Auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly rmqService: RabbitMQService,
  ) {}

  @UseGuards(LocalAuthGuard)
  @Post('/login')
  @ApiBody({ type: LoginUserDTO })
  @HttpCode(HttpStatus.OK)
  async login(@Request() userRequest: RequestUser) {
    return this.authService.login(userRequest.user);
  }
  @ApiBearerAuth('access-token')
  @UseGuards(AccessJwtAuthGuard)
  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Request() userRequest: any) {
    return this.authService.logout(userRequest.user);
  }

  @UseGuards(RefreshJwtAuthGuard)
  @Post('/refreshToken')
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.OK)
  async refreshToken(@Request() userRequest: any) {
    return this.authService.refreshToken(userRequest.user);
  }

  @MessagePattern('generate_token_user')
  async generateTokenForUser(
    @Payload() dataUser: any,
    @Ctx() context: RmqContext,
  ) {
    const user = await this.authService.getTokens(dataUser);
    this.rmqService.ack(context);
    return user;
  }

  @EventPattern('save_user_with_token')
  async saveUserCreatedWithToken(
    @Payload() dataUser: any,
    @Ctx() context: RmqContext,
  ) {
    const user = await this.authService.saveUserCreatedWithToken(dataUser);
    this.rmqService.ack(context);
    return user;
  }

  @Get('/google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth() {
    return;
  }

  @Get('/google/redirect')
  @UseGuards(GoogleAuthGuard)
  async googleAuthRedirect(@Request() req: any) {
    return await this.authService.googleLogin(req);
  }

  @UseGuards(AccessJwtAuthGuard)
  @Get('/profile')
  @ApiBearerAuth('access-token')
  getProfile(@Request() userRequest: any) {
    return userRequest.user;
  }
}
