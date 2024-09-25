const express=require('express');
const path=require('path');
const cors=require('cors');
const {open}=require('sqlite');
const sqlite3= require('sqlite3');
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const dbPath=path.join(__dirname,'todos.db');
const {v4: uuid}=require('uuid');
const app=express();
app.use(express.json());
app.use(cors({
    origin:'*',
    methods:['GET','POST','PUT','DELETE'],
    credentials:true
}));
let db=null;


// initializing server with sqlite3 database
const initializeDBandServer=async()=>{
    try {
        db=await open({
            filename:dbPath,
            driver:sqlite3.Database
        })
        
        app.listen(3004,()=>{
            console.log('server connected to 3004...')
        })

        await db.run(`
                CREATE TABLE IF NOT EXISTS users(
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )
            `)
        await db.run(`
                CREATE TABLE IF NOT EXISTS todos(
                    todo_id TEXT,
                    todo_title TEXT NOT NULL,
                    todo_status TEXT,
                    user_id TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            `)

        // await db.run(`drop table users`)


        
    } catch (error) {
        console.error(error)
        process.exit(1)
    }
}
initializeDBandServer()

// authenticating jwt token
const authenticateToken=async(req,res,next)=>{
    const tokenHeader=req.headers['authorization']
    const token=tokenHeader.split(' ')[1]
    // console.log(token)
    if(!token){
        res.status(403)
        res.send({msg:'token expired or not available'})
    }
    jwt.verify(token,'my_secret_key',(err,user)=>{
        if(err){
            res.status(403)
            res.send({msg:'invalid token'})
        }
        req.user=user
        next()
    })

}

// server checking
app.get('/',async(req,res)=>{
    res.send('checking query..')
})

// user registration with checking user exists or not
app.post('/add-user',async(req,res)=>{
    const {name,email,password}=req.body;
    const id=uuid()
    const hashedPassword= await bcrypt.hash(password,10)
    const verifyingUser=await db.get(`select * from users where email=?`,[email])
    if(verifyingUser){
        res.status(402)
        res.send({msg:'user already exists please login using this email.'})
    }else{
        const query=`insert into users(id,name,email,password) values(?,?,?,?)`
        const response=await db.run(query,[id,name,email,hashedPassword])
        if(response.changes>0){
            res.status(200)
            res.send({msg:'user created successfully..'})
        }
    }
    
})

// user login
app.post('/user-login',async(req,res)=>{
    const {name,email,password}=req.body;
    const verifyingUser=await db.get(`select * from users where email=?`,[email])
    if(verifyingUser){
        const isMatch=await bcrypt.compare(password,verifyingUser.password)
        if(isMatch){
            const jwtToken=jwt.sign({id:verifyingUser.id},'my_secret_key')
            res.status(200)
            res.send({token:jwtToken})
        }else{
            res.status(400)
            res.send({msg:'invalid password'})
        }
    }else{
        res.status(404)
        res.send({msg:'user not exists please register.'})
    }
})

//user details with authentication of user
app.get('/user-details',authenticateToken,async(req,res)=>{
    const {id}=req.user
    const query=`select * from users where id=?`
    try {
        const response=await db.get(query,[id])
        res.status(200)
        res.send(response)
    } catch (error) {
        res.status(400)
        console.log(error)
        res.send(error)
    }
})

//update user details
app.put('/update-user',authenticateToken,async(req,res)=>{
    const {id}=req.user
    const {name,email,password}=req.body
    const hashedPassword=await bcrypt.hash(password,10)
    const query=`update users set name=?,email=?,password=? where id=?`
    try {
        const response=await db.run(query,[name,email,hashedPassword,id])
        if(response.changes>0){
            res.status(200)
            res.send({msg:'user updated successfully..'})
        }
    }catch(error){
        res.status(402)
        res.send({msg:`error updating user`})
    }

})

//delete user from database
app.delete('/delete-user',authenticateToken,async(req,res)=>{
    const {id}=req.user
    const query=`delete from users where id=?`
    try {
        const response=await db.run(query,[id])
        if(response.changes>0){
            res.status(200)
            res.send({msg:'user deleted success fully'})
        }
    } catch (error) {
        res.status(400)
        res.send({msg:'error deleting user'})
    }
})

// list of todos of specific user
app.get('/get-todos',authenticateToken,async(req,res)=>{
    const {id}=req.user
    const userExists=await db.get(`select * from users where id=?`,[id])
    if(!userExists){
        res.status(400)
        res.send({msg:'user not available please register or login'})
    }
    const query=`select * from todos where user_id=?`
    try {
        const response=await db.all(query,[id])
        res.status(200)
        res.send(response)
    } catch (error) {
        res.status(400)
        res.send({msg:'error getting todos of this user'})
    }
})

// adding todo
app.post('/add-todo',authenticateToken,async(req,res)=>{
    const {id}=req.user
    const {todo_title,todo_status}=req.body
    const todo_id=uuid()
    const query=`insert into todos (todo_id,user_id,todo_title,todo_status) values (?,?,?,?)`
    try {
        const response=await db.run(query,[todo_id,id,todo_title,todo_status])
        if(response.changes>0){
            res.status(200)
            res.send({msg:'todo added successfully'})
        }
    } catch (error) {
        res.status(400)
        res.send({msg:'error adding todo'})
    }
})

// updating todo with authentication
app.put('/update-todo/:todoId',authenticateToken,async(req,res)=>{
    const {id}=req.user
    const {todoId}=req.params
    const {todo_title,todo_status}=req.body
    const query=`update todos set todo_title=?,todo_status=? where user_id=? and todo_id=?`
    try {
        await db.run(query,[todo_title,todo_status,id,todoId])
        res.status(200)
        res.send({msg:'todo updated successfully'})
    } catch (error) {
        res.status(400)
        res.send({msg:'Error updating todo'})
    }
})

// deleting todo from todos with authentication
app.delete('/delete-todo/:todoId',authenticateToken,async(req,res)=>{
    const {id}=req.user
    const {todoId}=req.params
    const query=`delete from todos where user_id=? and todo_id=?`
    try {
        await db.run(query,[id,todoId])
        res.status(200)
        res.send({msg:'todo deleted successfully'})
    }catch(err){
        res.status(400)
        res.send({msg:'error deleting todo'})
    }
})

module.exports=app