class User{

    constructor(username, password){
        this._uuid = uuidv4()
        this.username = username
        this.password = password
    }

    get uuid(){
        return this._uuid
    }

    get username(){
        return this.username
    }
    
    get password(){
        return this.password
    }

    set username(username){
        this._username = username
    }

    set password(password){
        this._password = password
    }
}

//creo stringa pseudocasuale da assegnare come identificativo univoco all'utente
function uuidv4() {
    return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, c =>
          (+c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> +c / 4).toString(16));
}

module.exports = User