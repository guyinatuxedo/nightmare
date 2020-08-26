# Whitehat 2018 re06

Let's take a look at the binary:

```
$    file reverse.exe reverse.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
```

So we can see that it is another .NET program. This means that it is compiled to an intermediate language instead of just machine code. Also due to it's design, we can decompile it to pretty much it's original source code (makes reversing it a lot easier). When we run it, we see that it presents us with a gui that prompts us for a key. Taking a look at the code in JetBrains, we see the code responsible for checking our input:

```
    public static string Enc(string s, int e, int n)
    {
      int[] numArray1 = new int[s.Length];
      for (int index = 0; index < s.Length; ++index)
        numArray1[index] = (int) s[index];
      int[] numArray2 = new int[numArray1.Length];
      for (int index = 0; index < numArray1.Length; ++index)
        numArray2[index] = MainWindow.mod(numArray1[index], e, n);
      string s1 = "";
      for (int index = 0; index < numArray1.Length; ++index)
        s1 += (string) (object) (char) numArray2[index];
      return Convert.ToBase64String(Encoding.Unicode.GetBytes(s1));
    }

    public static int mod(int m, int e, int n)
    {
      int[] numArray = new int[100];
      int index1 = 0;
      do
      {
        numArray[index1] = e % 2;
        ++index1;
        e /= 2;
      }
      while ((uint) e > 0U);
      int num = 1;
      for (int index2 = index1 - 1; index2 >= 0; --index2)
      {
        num = num * num % n;
        if (numArray[index2] == 1)
          num = num * m % n;
      }
      return num;
    }

    private void btn_check_Click(object sender, RoutedEventArgs e)
    {
      if (MainWindow.Enc(this.tb_key.Text, 9157, 41117) == "iB6WcuCG3nq+fZkoGgneegMtA5SRRL9yH0vUeN56FgbikZFE1HhTM9R4tZPghhYGFgbUeHB4tEKRRNR4Ymu0OwljQwmRRNR4jWBweOKRRyCRRAljLGQ=")
      {
        int num1 = (int) MessageBox.Show("Correct!! You found FLAG");
      }
      else
      {
        int num2 = (int) MessageBox.Show("Try again!");
      }
    }
```

So we can see, it takes our input and passes it to the `Enc` function along with the arguments `9157` and `41117`. It checks the output, and if it is equal to that string then it will print a message saying we have the flag.

Looking at the `enc` function, it looks like it just takes every character of our input and runs it through the `mod` function with the `9157` and `41117` values as the second and third arguments. It then takes the output of all of the `mod` calls, base64 encodes it, then returns the string Taking a look at the `mod` function shows us the bulk of what we need to.

For the mod function, we see it initializes `numArray` with values ranging from `0-1` (depends entirely on the second argument). It will then enter into a for loop where it will perform a series of multiplication and modular operations against `num`. After this loop the value of `num` is returned.

So we know that we give input to the program, it is run through an algorithm (that we know), and compared to a final result that we know. Looking at the `mod` function it looks like an AES encryption algorithm (however atm I'm not a crypto guy). I first tried to throw Z3 at this, however it couldn't get it to be able to solve it easily. So I just went the brute force method. When we base 64 decode the string, we see it is only `86` bytes

```
>>> import base64
>>> x = base64.b64decode("iB6WcuCG3nq+fZkoGgneegMtA5SRRL9yH0vUeN56FgbikZFE1HhTM9R4tZPghhYGFgbUeHB4tEKRRNR4Ymu0OwljQwmRRNR4jWBweOKRRyCRRAljLGQ=")
>>> len(x)
86
>>>
```
Since we know the output, and the only unknown is a single byte input, we can brute force it in practically no time. When I rewrote the `mod` function in python and tested it we see that it always outputs two bytes worth of data. So we the key we input will only be 43 characters long. Without knowledge we can brute force it one character at a time, which effectively reduces the work to only `43*256` runs to brute force it (even less if we limit it to ascii characters). Putting it together, we get the following script:

```
# https://github.com/p4-team/ctf/blob/master/2018-08-18-whitehat/re06/README.md
# ^ That writeup helped me with unpacking issues

import base64
import struct


def mod(m, e, n):
    numArray = [0]*100
    index1 = 0
    while e > 0:
        numArray[index1] = e % 2
        index1 = index1 + 1
        e = e / 2
    num = 1
    index2 = index1 - 1
    while index2 >= 0:
        num = num * num % n
        if (numArray[index2] == 1):
            num = num * m % n
        index2 = index2 - 1
    return (num )

base64encodeString = "iB6WcuCG3nq+fZkoGgneegMtA5SRRL9yH0vUeN56FgbikZFE1HhTM9R4tZPghhYGFgbUeHB4tEKRRNR4Ymu0OwljQwmRRNR4jWBweOKRRyCRRAljLGQ="
desiredOutput = base64.b64decode(base64encodeString)

flag = ""
for i in range(0, len(desiredOutput), 2):
    # Restrict it to ASCII characters first
    for c in range(33, 128):
        out = mod(c, 9157, 41117)
        check = struct.unpack("H", desiredOutput[i:i+2])[0]
        if (out == check):
            flag += chr(c)

print flag
```

We can see when we run the script, it gives us the flag. Also the writeup https://github.com/p4-team/ctf/blob/master/2018-08-18-whitehat/re06/README.md helped me with unpacking issues I was having:

```
$    python rev.py
WhiteHat{N3xT_t1m3_I_wi11_Us3_l4rg3_nUmb3r}
```

When we give the program the string `WhiteHat{N3xT_t1m3_I_wi11_Us3_l4rg3_nUmb3r}`, it confirms that we got the right input. With that, we captured the flag!
