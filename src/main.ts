import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { RabbitMQService } from './libs/common/src';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe());
  const rmqService = app.get<RabbitMQService>(RabbitMQService);
  app.connectMicroservice(rmqService.getOptions('AUTH'));
  app.enableCors({
    origin: 'http://localhost:3000',
  });
  await app.startAllMicroservices();
  await app.listen(process.env.PORT);
}
bootstrap();
