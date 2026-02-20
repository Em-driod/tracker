import 'dotenv/config';
import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors'; // npm install cors
import helmet from 'helmet'; // npm install helmet
import routes from './routes';
import connectDB from './config/database';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yamljs';
import path from 'path';

const app: Express = express();
const port = process.env.PORT || 3000; // Use env variable

// 1. Security & Parsing Middleware
app.use(helmet());
app.use(cors({
  origin: '*', // Allow all origins
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// 2. Health Check Endpoint
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// 3. Documentation
const swaggerDocument = YAML.load(
  path.resolve(process.cwd(), 'swagger.yaml')
);


// 4. Routes
app.use('/api', routes);

// 5. Global Error Handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 6. Connect to DB THEN Start Server
connectDB().then(() => {
  app.listen(port, () => {
    console.log(`🚀 Server ready at http://localhost:${port}`);
  });
}).catch(err => {
  console.error('Database connection failed', err);
  process.exit(1);
});