import { ApiProperty } from '@nestjs/swagger';
export class LoginUserDTO {
  @ApiProperty({ type: String, description: 'email or phoneNumber' })
  username: string;
  @ApiProperty({ type: String, description: 'password' })
  password?: string;
}

export class PayloadDTO {
  username: string;
  userId: string;
}

export class Tokens {
  accessToken: string;
  refreshToken: string;
}

export class TokenGoogle {
  @ApiProperty({ type: String, description: 'One time token google' })
  oneTimeToken: string;
}

export class RequestUser {
  user: UserSignIn;
}

export class UserSignIn {
  id: string;
  username: string;
  email: string;
  phoneNumber: string;
  address: string;
  role: string;
  status: string;
  gender: string;
  dateOfBirth: Date;
  avatar: string;
  isActive: boolean;
  provider: string;
  salesmanId: string;
}
