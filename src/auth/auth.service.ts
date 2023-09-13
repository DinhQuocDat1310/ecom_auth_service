import { lastValueFrom } from 'rxjs';
import {
  Injectable,
  Inject,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { GOOGLE_PROVIDER, USER_SERVICE } from './constants/service';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/service';
import { ConfigService } from '@nestjs/config';
import { Tokens } from './dto/auth';
import { hash, compare } from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    @Inject(USER_SERVICE) private readonly userClient: ClientProxy,
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  validateUser = async (username: string, password: string): Promise<any> => {
    // Send message to user-microservice to notify them we need to check username and password
    return await lastValueFrom(
      this.userClient.send('check_validate_user', {
        username,
        password,
      }),
    );
  };

  saveUserCreatedWithToken = async (dataUser: any): Promise<any> => {
    const hashedRefreshToken = await hash(dataUser.hashedRefreshToken, 10);
    const existedUserId = await this.prismaService.auth.findUnique({
      where: {
        userId: dataUser.id,
      },
    });
    return existedUserId
      ? await this.prismaService.auth.update({
          data: {
            hashedRefreshToken,
          },
          where: {
            userId: dataUser.id,
          },
        })
      : await this.prismaService.auth.create({
          data: {
            userId: dataUser.id,
            hashedRefreshToken,
          },
        });
  };

  login = async (user: any): Promise<Tokens> => {
    try {
      const tokens: Tokens = await this.getTokens(user);
      if (tokens) {
        user['hashedRefreshToken'] = tokens.refreshToken;
        await this.saveUserCreatedWithToken(user);
      }
      return tokens;
    } catch (error) {
      throw new InternalServerErrorException(error.message);
    }
  };

  getUserByEmailorPhonenumber = async (username: string): Promise<any> => {
    // Send message to user-microservice to notify them we need to find user by email or phonenumber
    return await lastValueFrom(
      this.userClient.send('find_user_by_email_or_phone', username),
    );
  };

  logout = async (user: any) => {
    try {
      await this.prismaService.auth.update({
        where: {
          userId: user.id,
          hashedRefreshToken: {
            not: null,
          },
        },
        data: {
          hashedRefreshToken: null,
        },
      });
      return;
    } catch (error) {
      throw new InternalServerErrorException(error.message);
    }
  };

  refreshToken = async (userData: any) => {
    const user = await this.prismaService.auth.findUnique({
      where: {
        userId: userData.id,
      },
    });
    if (!user) throw new UnauthorizedException();
    const compareRefreshToken = await compare(
      userData.refreshToken,
      user.hashedRefreshToken,
    );
    if (!compareRefreshToken) throw new UnauthorizedException();
    const tokens: Tokens = await this.getTokens(userData);
    if (tokens) {
      userData['hashedRefreshToken'] = tokens.refreshToken;
      await this.saveUserCreatedWithToken(userData);
    }
    return tokens;
  };

  googleLogin = async (req: any) => {
    if (!req.user) throw new UnauthorizedException();
    try {
      if (req.user.provider.toLowerCase() === GOOGLE_PROVIDER)
        return {
          message: 'User information from Google',
          user: req.user,
        };
    } catch (error) {
      throw new UnauthorizedException(error.message);
    }
  };

  getTokens = async (user: any): Promise<Tokens> => {
    const payload = {
      username: user.email ? user.email : user.phoneNumber,
      sub: user.id,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('ACCESS_TOKEN_JWT_SECRET_KEY'),
        expiresIn: 60 * 60 * 24, // 24 hours
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('REFRESH_TOKEN_JWT_SECRET_KEY'),
        expiresIn: 60 * 60 * 24 * 7, //7 days
      }),
    ]);
    return {
      accessToken,
      refreshToken,
    };
  };
}
