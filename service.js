const jwt = require('jsonwebtoken');
const express = require('express');
 const cors = require('cors');
 const bcrypt = require('bcrypt');

const { PrismaClient } = require('./generated/prisma');
const app = express();
const prisma = new PrismaClient();
require('dotenv').config();
app.use(cors());
app.use(express.json());

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization?req.headers.authorization:  req.query.token;
    if (!authHeader) {
         res.status(401).json({ message: 'Token Not Found' });
    } else {
        const token = authHeader && authHeader.split(" ")[1];
        if (token == null) {
           res.status(401).json({ message: 'Token Not Found' });
        } else {
            jwt.verify(token, process.env.JWT_SECRET||"Rexcoder", (err, user) => {
                if (err) {
                  res.status(401).json({ message: 'Error', error:err });
                   
                }
                req.user = user;
              if (user.exp && Date.now() >= user.exp * 1000) {
      return res.status(401).json({ message: "Token Expired" });
    }
              
                else{
                    next();
                }
            });
        }
    }
}

app.post('/signup', async (req, res) => {
  try {
    const {  email, password,name } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
    const user = await prisma.user.create({
      data: {
         email,
        password: hashedPassword,
        name
      }
    });

    res.status(201).json({ message: 'User created', user });
  } catch (error) {
  
    console.error('Signup Error:', error);
    res.status(500).json({ error: 'Signup failed' });
  }
});


app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;


    const user = await prisma.user.findUnique({
      where: { email }
    });

      if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

   const token = jwt.sign(
      { id: user.id, email: user.email },
       process.env.JWT_SECRET,  
      { expiresIn: process.env.JWT_EXPIRES_IN}
    );

    res.status(200).json({
      message: 'Login successful',
      token
    });
    
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});
app.post('/task',authenticateToken, async (req, res) => {
  try {
    const { task, completed } = req.body;
   
const {user}= req;
    const newTask = await prisma.task.create({
      data: {
        task,
        isCompleted:completed,
         userId: user.id
      },
    });
    res.status(201).json({ message: 'Task added successfully', task: newTask });
  } catch (error) {
    console.error('Error adding task:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/task',authenticateToken, async (req, res) => {
  try {
    const {user} =req;
    const tasks = await prisma.task.findMany({
      where: { isDeleted: false,  userId:user.id },
      orderBy: {id:'desc'}
    });
    res.json(tasks);
  } catch (error) {
    res.status(500).json({ error: 'Unable to fetch tasks' });
  }
});

app.put('/task/:id', async (req, res) => {
  try {
    const { isCompleted } = req.body; 

    const updatedTask = await prisma.task.update({
      where: { id: parseInt(req.params.id) }, 
      data: { isCompleted: Boolean(isCompleted) }, 
    });

    res.json(updatedTask);
  } catch (error) {
    console.error("Error updating task:", error);
    res.status(500).json({ error: 'Unable to update task' });
  }
});

app.delete('/task/:id', async (req, res) => {
  try {
  

    const deleteTask = await prisma.task.delete({
      where: { id: parseInt(req.params.id) }, 
      
    });

    res.json(deleteTask);
  } catch (error) {
    console.error("Error updating task:", error);
    res.status(500).json({ error: 'Unable to update task' });
  }
});

const PORT = 4000;
app.listen(PORT, () => {
  console.log(` Server running at http://localhost:${PORT}`);
});
