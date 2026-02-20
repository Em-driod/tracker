import dotenv from 'dotenv';
import { hashPassword } from '../utils/password';
import { User } from '../models/user.model';
import connectDB from '../config/database';

dotenv.config();

const createTestUser = async () => {
  try {
    await connectDB();
    
    const testUser = {
      fullName: 'Test User',
      email: 'testuser@finwise.com',
      username: 'testuser_finwise',
      dateOfBirth: new Date('1990-01-01'),
      password: await hashPassword('TestPass123!'),
      isVerified: true,
      lastActivityAt: new Date(),
    };

    // Check if user already exists
    const existingUser = await User.findOne({ email: 'testuser@finwise.com' });
    if (existingUser) {
      console.log('Test user already exists');
      return;
    }

    const user = new User(testUser);
    await user.save();
    
    console.log('✅ Test user created successfully:');
    console.log('Email: testuser@finwise.com');
    console.log('Password: TestPass123!');
    console.log('Username:', user.username);
    
  } catch (error) {
    console.error('Error creating test user:', error);
  } finally {
    process.exit(0);
  }
};

createTestUser();
