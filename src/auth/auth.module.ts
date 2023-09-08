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
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  imports: [
    RabbitMQModule.register({
      name: USER_SERVICE,
    }),
    PassportModule,
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => {
        return {
          secret: configService.get<string>('JWT_SECRET_KEY'),
          signOptions: {
            expiresIn: '86400', //24 hours
          },
        };
      },
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, RabbitMQService, LocalStrategy, JwtStrategy],
})
export class AuthModule {}
