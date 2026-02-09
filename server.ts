import 'dotenv/config';
import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors'; // npm install cors
import helmet from 'helmet'; // npm install helmet
import routes from './src/routes';
import connectDB from './src/config/database';
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

// 2. Documentation
const swaggerDocument = YAML.load(path.join(__dirname, './swagger.yaml'));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// 3. Routes
app.use('/api', routes);

// 4. Global Error Handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 5. Connect to DB THEN Start Server
connectDB().then(() => {
  app.listen(port, () => {
    console.log(`🚀 Server ready at http://localhost:${port}`);
  });
}).catch(err => {
  console.error('Database connection failed', err);
  process.exit(1);
});