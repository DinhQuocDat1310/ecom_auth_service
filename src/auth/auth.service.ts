import { lastValueFrom } from 'rxjs';
import {
  Injectable,
  Inject,
  InternalServerErrorException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import {
  EMAIL_VERIFIED,
  GOOGLE_PROVIDER,
  PURCHASER_ROLE,
  SALESMAN_ROLE,
  USER_SERVICE,
} from './constants/service';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/service';
import { ConfigService } from '@nestjs/config';
import { TokenGoogle, Tokens } from './dto/auth';
import { hash, compare } from 'bcrypt';
import { LoginTicket, OAuth2Client } from 'google-auth-library';

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
    return await this.prismaService.auth.create({
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
    userData['is_refresh'] = true;
    const tokens: Tokens = await this.getTokens(userData);
    if (tokens) userData['hashedRefreshToken'] = tokens.refreshToken;
    return tokens;
  };

  salesmanLoginGoogle = async (token: TokenGoogle): Promise<string> => {
    try {
      const googleClientID: string = this.configService.get('GOOGLE_CLIENT_ID');
      const googleSecretKey: string =
        this.configService.get('GOOGLE_SECRET_KEY');
      const clientOAuth: OAuth2Client = new OAuth2Client(
        googleClientID,
        googleSecretKey,
      );
      const ticket: LoginTicket = await clientOAuth.verifyIdToken({
        idToken: token.oneTimeToken,
        audience: googleClientID,
      });
      const { name, picture, email } = ticket.getPayload();
      const user = {
        username: name,
        avatar: picture,
        email,
        provider: GOOGLE_PROVIDER,
        status: EMAIL_VERIFIED,
        role: SALESMAN_ROLE,
      };
      return await lastValueFrom(
        this.userClient.send('create_user_login_google', user),
      );
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  };

  purchaserLoginGoogle = async (token: TokenGoogle): Promise<string> => {
    try {
      const googleClientID: string = this.configService.get('GOOGLE_CLIENT_ID');
      const googleSecretKey: string =
        this.configService.get('GOOGLE_SECRET_KEY');
      const clientOAuth: OAuth2Client = new OAuth2Client(
        googleClientID,
        googleSecretKey,
      );
      const ticket: LoginTicket = await clientOAuth.verifyIdToken({
        idToken: token.oneTimeToken,
        audience: googleClientID,
      });
      const { name, picture, email } = ticket.getPayload();
      const user = {
        username: name,
        avatar: picture,
        role: PURCHASER_ROLE,
        email,
        provider: GOOGLE_PROVIDER,
        status: EMAIL_VERIFIED,
      };
      return await lastValueFrom(
        this.userClient.send('create_user_login_google', user),
      );
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  };

  getTokens = async (user: any): Promise<Tokens> => {
    const payload = {
      username: user.email ? user.email : user.phoneNumber,
      sub: user.id,
    };
    const generateTokenType = [];
    const accessTokenType = this.jwtService.signAsync(payload, {
      secret: this.configService.get('ACCESS_TOKEN_JWT_SECRET_KEY'),
      expiresIn: 60 * 60 * 24, // 24 hours
    });
    const refreshTokenType = this.jwtService.signAsync(payload, {
      secret: this.configService.get('REFRESH_TOKEN_JWT_SECRET_KEY'),
      expiresIn: 60 * 60 * 24 * 7, //7 days
    });

    user['is_refresh']
      ? generateTokenType.push(accessTokenType)
      : generateTokenType.push(accessTokenType, refreshTokenType);

    const [accessToken, refreshToken] = await Promise.all(generateTokenType);
    return {
      accessToken,
      refreshToken,
    };
  };
}
