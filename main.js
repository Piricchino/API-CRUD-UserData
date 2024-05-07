const fastify = require('fastify')({ logger: true })
const fastifyCookie = require('@fastify/cookie')
const bcrypt = require('bcrypt')

const fs = require('fs/promises')
const User = require('./User')
const Util = require('./Util')

//necessario per utilizzare i cookies
fastify.register(fastifyCookie)

//Parser per leggere tutte le richieste in json
fastify.addContentTypeParser('application/jsoff', async function (req) {
	var res = await new Promise((resolve, reject) => resolve(req))
	return res
})

//Routes dove è necessaria l'autenticazione per ottenere le risorse
fastify.register((instance, opts, done) => {
	instance.decorate('validateToken', Util.validateToken)
    /**//*
	const userSchema = {
		$id: 'userSchema',
		type: 'object',
		properties: {
			id: { type: 'string' },
			data: { type: 'object' }
		}
	}

	const schema = {
		body: userSchema
	}

	instance.addSchema(schema)
*/
	
	//Schema dati utente
	instance.addSchema( {
		$id: 'userSchema',
		body: {
			$id: 'bodySchema',
			type: 'object',
			properties: {
				id: { type: 'string' },
				data: { type: 'object' }
			}
		}
	})
  
	//hook per eseguire validateToken in ogni route di instance con opzione preHandler
	instance.addHook('preHandler', async (request, reply) => {
		await instance.validateToken(request, reply)
	})

	//recupero tutti i file di un utente
	instance.get('/data', async function (req, reply) {
		const path = "data/" + req.cookies['userId']
		var allData = new Array()
		const files = await fs.readdir(path)
		try {
			for (const file of files) {
				console.log(file)
				let idS = file.split(".")[0]
				let dataS = JSON.parse(await fs.readFile(path + "/" + file))
				let parsedFile = {id: idS, data: dataS}
				console.log(parsedFile)
				allData.push(parsedFile)
			}
	
			return reply.status(200).send(allData)
		} catch (err) {
			return reply.status(400).send(err)
		}
	})

	//restituisco i dati in base al parametro id
	instance.get('/data/:id', async function (req, reply) {
		var fileFounded = null
		let found = await Util.findOneFile(req)
		const userDataPath = "data/" + req.cookies['userId']
		if(found) {
			try{
				fileFounded = await fs.readFile(userDataPath + "/" + found)
				return reply.status(200).send(fileFounded)
			} catch(err) {
				return reply.status(400).send(err)
			}
		} else {
			return reply.status(400).send("Nessun File trovato!")
		}
	})
	
	//creo un file 
	instance.post('/data', async function (req, reply) {
		req.params.id = req.body.id
		let find = await Util.findOneFile(req)
		
		if(find != null) return reply.status(400).send("File già esistente!")
		
		const { id, data } = req.body
		if ((id, data != null) && (id != "")) {
			try {
				let path = "data/" + req.cookies["userId"] + "/" + id + ".json"
				await fs.writeFile(path, JSON.stringify(data))
				return reply.status(200).send("File caricato correttamente!")
			} catch (err) {
				console.error(err);
				return reply.status(400).send({ error: err })
			}
		} else {
			return reply.status(400).send("Errore inserimento dati!")
		}
	})

	//aggiorno il contenuto del file dato il suo id
	instance.put('/data/:id', async function(req, reply) {
		/**/const {data} = req.body
		var found = await Util.findOneFile(req)
		const userDataPath = "data/" + req.cookies['userId']
		
		if(found && (data != null)) {
			try{
				await fs.writeFile(userDataPath + "/" + found, JSON.stringify(data))
				reply.status(200).send("File aggiornato correttamente!")
			} catch(err) {
				reply.status(400).send(err)
			}
		} else {
			reply.status(400).send("Nessun File trovato!")
		}
	})

	//elimino un file dato il suo id
	instance.delete('/data/:id', async function(req, reply) {
		var found = await Util.findOneFile(req)
		const userDataPath = "data/" + req.cookies['userId']
		
		if(found) {
			try{
				/**/await fs.unlink(userDataPath + "/" + found)
				reply.status(200).send("File eliminato correttamente!")
			} catch(err) {
				reply.status(400).send(err)
			}
		} else {
			reply.status(400).send("Nessun File trovato!")
		}
	})

	//logout (pulisco i cookie)
	instance.post("/logout", function (req, reply) {
		reply.clearCookie("accessToken")
		reply.clearCookie("userId")
		return reply.status(200).send("Logout effettuato correttamente!")
	})
  
	done()
})

//Crea un nuovo user data username e password
fastify.post('/register', async function (req, reply) {
	const {username, password} = req.body
	console.log("username: ", username)
	console.log("password: ", password)
	//controllo che non vi sia già un utente con lo stesso nome
	let found = await Util.findOneUsername(username)
	
	if(found){
		return reply.status(400).send("nome utente non disponibile!")
	} else {
		//creo hash password da salvare nel db
		const hash = await bcrypt.hash(password, 10)
		const user = new User(username, hash)

		try {
			//salvo l'utente creato 
			await fs.writeFile(Util.userPath(user), JSON.stringify(user))
			//creo una cartella per inserire i suo dati futuri
			await fs.mkdir(Util.mkdirUser(user))
			return reply.status(200).send("user creato correttamente!")
		} catch (err) {
			console.error(err);
			return reply.status(400).send(err)
		}
	}	

})

//route per eseguire il login, restituisce una risposta con cookie settato con accessToken (jwt) e userId (db)
fastify.post('/login', async function(req, reply) {
	const {username, password} = req.body
	//controllo che l'utente esista per procedere con la creazione del token
	var found = await Util.findOneUsername(username)

	if(found){
		//verifico la correttezza della password confrontandola con l'hash salvato sul db
		let compared = await bcrypt.compare(password, found._password)
		
		if (compared) {
			//creo il token per la sessione
			const accessToken = Util.createToken(found)

			//setto i cookie necessari per poi poterli usare in middleware e db
			reply.setCookie('accessToken', accessToken, {
				maxAge: 5000000,
				httpOnly: true
			})
			reply.setCookie('userId', found._uuid,  {
				maxAge: 5000000,
				httpOnly: true
			})
			return reply.status(200).send("LOGGED IN!")
		} else {
			return reply.status(400).send("password errata!")
		}	
		
	} else {
		return reply.status(400).send("Utente non trovato!")
	}
})

// Run the server!
fastify.listen({ port: 3000 }, function (err, address) {
	if (err) {
		fastify.log.error(err)
		process.exit(1)
	}
	console.log(`Server is now listening on ${address}`)
})