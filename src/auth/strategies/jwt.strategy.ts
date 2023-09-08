import { lastValueFrom } from 'rxjs';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PayloadDTO } from '../dto/auth';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET_KEY,
    });
  }

  async validate(payload: PayloadDTO) {
    const user = await this.authService.getUserByEmailorPhonenumber(
      payload.username,
    );
    const userAsPromise = await lastValueFrom(user);
    if (!userAsPromise) throw new UnauthorizedException();
    return userAsPromise;
  }
}
