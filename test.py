from scrumbledeggs import Crypto


password = "ThisIsAPassword"
messages = ["Lasciate ogni speranza, o voi ch’entrate",
            "I costumi e le mode degli uomini cambiano come le foglie sul ramo, alcune delle quali vanno ed altre vengono.",
            "Perché quando lo strumento dell'intelligenza si somma alla forza bruta e alla malvagia volontà, il genere umano è impotente a difendere se stesso.",
            "Amor che nella mente mi ragiona cominciò egli a dir si dolcemente che la dolcezza ancor dentro mi suona."]

crypto = Crypto()
print("Encryption started")
print()
startTime = time.time()
for msg in messages:
    encrypted = crypto.encrypt(msg, password)
    decrypted = crypto.decrypt(encrypted, password)

    print("Original Msg: ", msg)
    print("Encrypted Msg: ", encrypted)
    print("Decrypted Msg; ", decrypted)
    print("Encryption ratio: ", len(encrypted) / len(decrypted))
    print()
print(f"Encrypted {len(messages)} messages in {time.time() - startTime} seconds")