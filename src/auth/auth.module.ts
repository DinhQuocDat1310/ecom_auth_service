import { RabbitMQModule } from './../libs/common/src/rabbitmq/rabbitmq.module';
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { RabbitMQService } from 'src/libs/common/src';
import { USER_SERVICE } from './constants/service';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AccessTokenJwtStrategy } from './strategies/access-token-jwt.strategy';
import { PrismaService } from 'src/prisma/service';
import { RefreshTokenJwtStrategy } from './strategies/refresh-token-jwt.strategy';

@Module({
  imports: [
    RabbitMQModule.register({
      name: USER_SERVICE,
    }),
    PassportModule,
    JwtModule.register({}),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    RabbitMQService,
    LocalStrategy,
    RefreshTokenJwtStrategy,
    AccessTokenJwtStrategy,
    ConfigService,
    PrismaService,
  ],
})
export class AuthModule {}
