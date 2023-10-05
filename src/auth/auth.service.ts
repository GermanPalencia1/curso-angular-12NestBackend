import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';
import { LoginDto } from './dto/login.dt';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      
      const {password, ...userData} = createUserDto;
      
      //1- Encriptar la contraseña

      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });
      
      //2- Guardar usuario
      
      await newUser.save();

      //3- Generar JSON WEB TOKEN


      const {password: _, ...user} = newUser.toJSON(); 

      return user;

    } catch(error) {

      if(error.code === 1100) {
        throw new BadRequestException(`${createUserDto.email} already exists`);
      } else {
        throw new InternalServerErrorException('Somethis terrible happened');
      }

    }

  }

  async login(loginDto: LoginDto) {

    //Verificación del usuario

    const { email, password} = loginDto;

    //Verificar email

    const user = await this.userModel.findOne({email});

    if(!user) {
      throw new UnauthorizedException('Not valid credentials - email');
    }

    //Verificar contraseña

    if(!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Not valid credentials - password');
    }

    //Respuesta

    const {password: _, ...rest} = user.toJSON();
    
    return {
      user: rest,
      token: 'ABC-123'
    }

  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
  
}
