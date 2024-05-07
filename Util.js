const fs = require('fs/promises')
const jwt = require('jsonwebtoken')

//verifico che non sia già presente un untente con lo stesso username
async function findOneUsername(userToCheck){
	let check = null
	try {
		const files = await fs.readdir("users")
		for (const file of files){
			const text = await fs.readFile("users/" + file, "utf8")
			const user = JSON.parse(text)

			if(userToCheck===user._username){
				check = user
				return check;
			}
		}

	} catch (err) {
		console.error(err)
	}

	return check;
}

//creo token JWT (valido per 30minuti)  //JWT SECRET DA CAMBIARE!
function createToken(user){
	const accessToken = jwt.sign({ username: user._username }, "JWTSECRETDACAMBIAREFORSEENVCONFIG", { expiresIn: '30m'})
	console.log("ACCESS TOKEN: ", accessToken)
	return accessToken
}

//middleware per verificare che lo user abbia fatto login e abbia un token valido //JWT SECRET DA CAMBIARE!
const validateToken = function(req, reply){
	const accessToken = req.cookies["accessToken"]
	if(!accessToken) return reply.status(400).send("Autenticazione necessaria!")

	try {
		//verifico la validità del token dato un "JWTSECRET"
		const validToken = jwt.verify(accessToken, "JWTSECRETDACAMBIAREFORSEENVCONFIG")
		if(validToken){
			return true
		}
	} catch(err) {
		return reply.status(400).send({ error: err })
	}
}

//cerco e restituisco un file se presente, null altrimenti
const findOneFile = async function(req){
	const path = "data/" + req.cookies['userId']
	const files = await fs.readdir(path)
	for (const file of files) {
		console.log(file)
		if (file.split(".")[0] === req.params.id) {
			let found = file
			console.log("Found: ", found)
			return found
		}
	}
	return null
}

const userPath = function(user){
	return "users/" + user.uuid + ".json"
}

const mkdirUser = function(user){
	return "data/" + user.uuid
}

module.exports = {findOneUsername, findOneFile, validateToken, createToken, userPath, mkdirUser}