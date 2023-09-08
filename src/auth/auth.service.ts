import { lastValueFrom } from 'rxjs';
import { Injectable, Inject } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { USER_SERVICE } from './constants/service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @Inject(USER_SERVICE) private readonly userClient: ClientProxy,
    private readonly jwtService: JwtService,
  ) {}

  validateUser = async (username: string, password: string): Promise<any> => {
    // Send message to user-microservice to notify them we need to check username and password
    return this.userClient.send('check_validate_user', {
      username,
      password,
    });
  };

  login = async (user: any): Promise<{ access_token: string }> => {
    const userAsPromise: any = await lastValueFrom(user);
    const payload = {
      username: userAsPromise.email
        ? userAsPromise.email
        : userAsPromise.phoneNumber,
      sub: userAsPromise.userId,
    };
    return {
      access_token: this.jwtService.sign(payload),
    };
  };

  getUserByEmailorPhonenumber = async (username: string) => {
    // Send message to user-microservice to notify them we need to find user by email or phonenumber
    return this.userClient.send('find_user_by_email_or_phone', username);
  };
}
