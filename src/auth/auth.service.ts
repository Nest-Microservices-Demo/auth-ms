import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { RpcException } from '@nestjs/microservices';
import { RegisterUserDto } from './dto/register-user.dto';
import * as bcrypt from "bcrypt";
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

  private readonly logger = new Logger("AuthService");

  constructor(
    private readonly jwtService: JwtService
  ) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log("MongoDB connection started");
  }

  async registerUser(registerUserDto: RegisterUserDto) {

    const { email, password, name } = registerUserDto;
    try {
      const user = await this.user.findUnique({
        where: {
          email: email
        },
      });

      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists'
        });
      }

      const newUser = await this.user.create({
        data: {
          email: email,
          password: bcrypt.hashSync(password, 10),
          name: name
        }
      });

      const { password: _, ...rest } = newUser;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };

    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message
      })
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {

    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({
        where: {
          email: email
        },
      });

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'Invalid credentials'
        });
      }

      const isValidPassword = bcrypt.compareSync(password, user.password);

      if (!isValidPassword) {
        throw new RpcException({
          status: 400,
          message: 'Invalid credentials'
        });
      }

      const { password: _, ...rest } = user;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };

    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message
      })
    }
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(
        token,
        {
          secret: envs.jwtSecret
        }
      );
      return {
        user: user,
        token: await this.signJWT(user),
      }
    } catch (error) {
      throw new RpcException({
        status: 401,
        message: "Invalid token"
      })
    }
  }

  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

}
