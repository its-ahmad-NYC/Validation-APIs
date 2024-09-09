const bcryptjs = require('bcryptjs')
const jwt = require('jsonwebtoken')
const UserModel = require('../Models/user')

const signup = async (req,res)=>{
    try{
        const {name,email, password}=req.body;
        const user = await UserModel.findOne({email})
        if(user){
            return res.status(409)
            .json({message: "User is already exist, you can login.", success: false})
        }
        const userModel = new UserModel({name, email, password})
        userModel.password= await bcryptjs.hash(password,10)
        await  userModel.save()
        res.status(201)
            .json({
                message: "Signup Successfully",
                success: true
            })
    }catch(error){
        res.status(500)
        .json({
            message: "Internal Server Error",
            success: true
        })
    }
}

const login= async (req,res)=>{

    try{
        const {email, password}=req.body;
        const user = await UserModel.findOne({email})
        const errorMsg = 'Authentication failed email or password is wrong'
        if(!user){
            return res.status(403)
            .json({message: errorMsg, success: false})
        }
        const isPassEqual = await bcryptjs.compare(password, user.password)
        if(!isPassEqual){
            return res.status(403)
            .json({message: errorMsg, success: false})
        }
        const jwtToken = jwt.sign({email: user.email, _id: user.id},
            process.env.JWT_SECRET,
            {expiresIn: '24h'}
        )
        res.status(200)
            .json({
                message:'Login SuccessFull',
                success: true,
                jwtToken,
                email,
                name: user.name
            })

    }catch(error){
        res.status(500)
        .json({
            message: 'Internal Server Error',
            success: true
        })
    }

}

module.exports={
    signup,
    login
}