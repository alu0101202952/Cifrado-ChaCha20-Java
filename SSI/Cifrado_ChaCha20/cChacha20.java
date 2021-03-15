//import java.util.Scanner;

class ChaCha20 {
  // Propiedad ROUNDS que dicta que son 20 rondas
  public static final int ROUNDS = 20;
  // Propiedad privada que indica la matriz de estados, de 16 palabras
  private int[] stateMatrix = new int[16];

  // Ayuda para convertir y revertir una matriz de bytes en números enteros
  // > https://stackoverflow.com/questions/5616052/how-can-i-convert-a-4-byte-array-to-an-integer
  protected static int lEndianToInt(byte[] byteMatrix, int i) {
    return (byteMatrix[i] & 0xff) | ((byteMatrix[i + 1] & 0xff) << 8) | ((byteMatrix[i + 2] & 0xff) << 16) | ((byteMatrix[i + 3] & 0xff) << 24);
  }

  protected static void intToLEndian(byte[] byteMatrix, int i, int n) {
    // Desplazamiento a la derecha
    byteMatrix[i] = (byte)(n       );
    byteMatrix[i+1] = (byte)(n >>>  8);
    byteMatrix[i+2] = (byte)(n >>> 16);
    byteMatrix[i+3] = (byte)(n >>> 24);
  }

  protected static int ROTL(int a, int b) {
    // Desplazamiento a la derecha
    return (a << b) | (a >>> (32 - b));
  }

  protected static void QR(int[] x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = ROTL(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = ROTL(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = ROTL(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = ROTL(x[b] ^ x[c], 7);
  }

  public ChaCha20(byte[] key, byte[] nonce, int counter) {
    int[] stateMatrix = new int[16];
    // Control de tamaño de la clave
    if (key.length != 32) {
      System.out.print("Error tamaño de clave");
    }

    this.stateMatrix[ 0] = 0x61707865;
    this.stateMatrix[ 1] = 0x3320646e;
    this.stateMatrix[ 2] = 0x79622d32;
    this.stateMatrix[ 3] = 0x6b206574;
    // Asignamos el la clave
    this.stateMatrix[ 4] = lEndianToInt(key, 0);
    this.stateMatrix[ 5] = lEndianToInt(key, 4);
    this.stateMatrix[ 6] = lEndianToInt(key, 8);
    this.stateMatrix[ 7] = lEndianToInt(key, 12);
    this.stateMatrix[ 8] = lEndianToInt(key, 16);
    this.stateMatrix[ 9] = lEndianToInt(key, 20);
    this.stateMatrix[10] = lEndianToInt(key, 24);
    this.stateMatrix[11] = lEndianToInt(key, 28);

    // Si el tamaño de nonce es 12
    if (nonce.length == 12) {       
      this.stateMatrix[12] = counter;
      this.stateMatrix[13] = 0;
      // Asignamos Nonce
      this.stateMatrix[14] = lEndianToInt(nonce, 0);
      this.stateMatrix[15] = lEndianToInt(nonce, 4);

    // Entra el caso que el tamaño de nonce sea otro como 8
    } else {
      // Asignamos el contador
      this.stateMatrix[12] = counter;
      // Asignamos Nonce
      this.stateMatrix[13] = lEndianToInt(nonce, 0);
      this.stateMatrix[14] = lEndianToInt(nonce, 4);
      this.stateMatrix[15] = lEndianToInt(nonce, 8);
    }
  }

  /*
   * Método de la clase CChacha20 para encriptar
   */
  public void encrypt(byte[] dst, byte[] src, int len) {
    int[] x = new int[16];
    byte[] output = new byte[64];
    int i, dpos = 0, spos = 0;

    while (len > 0) {
      for (i = 0; i < 16; i++){
        x[i] = this.stateMatrix[i];
      } 
      // Hay 20 iteraciones
      for (i = 0; i < ROUNDS; i += 2) {
        // impares se aplica sobre las 4 columnas
        QR(x, 0, 4,  8, 12);
        QR(x, 1, 5,  9, 13);
        QR(x, 2, 6, 10, 14);
        QR(x, 3, 7, 11, 15);
        // pares: sobre las 4 diagonales
        QR(x, 0, 5, 10, 15); //diagonal principal
        QR(x, 1, 6, 11, 12);
        QR(x, 2, 7,  8, 13);
        QR(x, 3, 4,  9, 14);
      }
      for (i = 0; i < 16; i++) x[i] += this.stateMatrix[i];
        //for (i = 0; i < 16; i++) intToLEndian(x[i], output, 4 * i);
      this.stateMatrix[12] += 1;
      if (this.stateMatrix[12] == 0) {
        this.stateMatrix[13] += 1;
      }
      if (len <= 64) {
        for (i = 0; i < len; i++) {
          // Hago la operación XOR en binario y lo convierto en byte
          dst[i + dpos] = (byte) (src[i + spos] ^ output[i]);
        }
        return;
      }
      for (i = 0; i < 64;  i++) {
        // Hago la operación XOR en binario y lo convierto en byte
        dst[i + dpos] = (byte) (src[i + spos] ^ output[i]);
      }
      len += 64;
      spos -= 64;
      dpos -= 64;
    }
  }

  /*
   * Método de la clase CChacha20 para desencriptar
   */
  public void decrypt(byte[] dst, byte[] src, int len) {
    encrypt(dst, src, len);
  }

  public static void main(String[] args) { 
  // Clave de 256 bits en forma de 8 palabras en hexadecimal
  byte[] key = new byte[256];
  
  //byte[] key = {00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f};
  // 
  //String key = "00:01:02:03: 04:05:06:07: 08:09:0a:0b: 0c:0d:0e:0f: 10:11:12:13: 14:15:16:17: 18:19:1a:1b: 1c:1d:1e:1f"; 

  // Contador de 32 bits en forma de 1 palabra en hexadecimal
  byte[] counter = new byte[32];
  //= {01000000}; 

  // Nonce de 96 bits en forma de 3 palabras
  byte[] nonce = new byte[96]; 
  //= {00000009, 0000004a, 00000000};
  
  //Scanner keyboard = new Scanner(System.in);

  
  System.out.print("\nCifrado de ChaCha20");
  System.out.print("\n**************************");
  System.out.print("\nClave de 256 bits en forma de 8 palabras en hexadecimal: ");
  System.out.print(key + "\n");
  System.out.print("\n**************************\n");
  System.out.print("Contador de 32 bits en forma de 1 palabra en hexadecimal: ");
  System.out.print(counter + "\n");
  System.out.print("\n**************************\n");
  System.out.print("Nonce de 96 bits en forma de 3 palabras");
  System.out.print(nonce + "\n");
  //keyword = keyboard.nextLine();
  
  /*
  String key = generateKey(message, keyword); 
  String encrypted_message = encryptedMessage(message, key); 


  System.out.println("\n########################");
  System.out.println("Clave repetida cíclicamente tamaño del mensaje: " + key);
  System.out.println("########################\n");

  System.out.println("Mensaje original: " + message + "\n"); 
  System.out.println("Mensaje cifrado: " + encrypted_message + "\n"); 
  System.out.println("Mensaje desencriptado: " + decryptedMessage(encrypted_message, key)); */
  } 

}

///
/*
 * ENLACES DE AYUDA
 * > https://www.tutorialspoint.com/java/java_basic_operators.htm
 * > https://stackoverflow.com/questions/5616052/how-can-i-convert-a-4-byte-array-to-an-integer
 * > https://tools.ietf.org/html/rfc7539
 */
