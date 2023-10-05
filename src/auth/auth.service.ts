import { BadRequestException, Injectable, InternalServerErrorException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>
  ) {}

  create(createUserDto: CreateUserDto): Promise<User> {

    try {

      const newUser = new this.userModel(createUserDto);

      //1- Encriptar la contraseña

      

      //2- Guardar usuario
      //3- Generar JWT

    } catch(error) {

      if(error.code === 1100) {
        throw new BadRequestException(`${createUserDto.email} already exists`);
      } else {
        throw new InternalServerErrorException('Somethis terrible happened');
      }

    }

    

    return newUser.save();

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
