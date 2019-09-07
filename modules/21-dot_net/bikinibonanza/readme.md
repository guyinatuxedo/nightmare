# Csaw 2013 bikinibonanza

Let's take a look at the binary

```
$    file bikinibonanza.exe
bikinibonanza.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
```

So we can see it is another .NET challenge. When we run it, we see that it is just a gui with a single form that prompts us for input (you may need to install a few Microsoft packages to get it to work). Looking at it with the JetBrains decompiler, we can see what is going on with the form:

```
    private void eval_ᜀ(object _param1, EventArgs _param2)
    {
      string strB = (string) null;
      Assembly executingAssembly = Assembly.GetExecutingAssembly();
      ResourceManager resourceManager = new ResourceManager(executingAssembly.GetName().Name + ".Resources", executingAssembly);
      DateTime now = DateTime.Now;
      string text = this.eval_ᜀ.Text;
      this.eval_ᜀ("NeEd_MoRe_Bawlz", Convert.ToInt32(string.Format("{0}", (object) (now.Hour + 1))), ref strB);
      if (string.Compare(text.ToUpper(), strB) == 0)
      {
        this.eval_ᜂ.Text = "";
        Form1 form1 = this;
        int num1 = 107;
        int num2 = (int) form1.eval_ᜀ(num1);
        form1.eval_ᜀ((char) num2);
        this.eval_ᜁ();
        this.eval_ᜂ.Text = string.Format(this.eval_ᜂ.Text, (object) this.eval_ᜀ(resourceManager));
        this.eval_ᜃ.Image = (Image) resourceManager.GetObject("Sorry You Suck");
      }
      else
      {
        this.eval_ᜃ.Image = (Image) resourceManager.GetObject("Almost There");
        this.eval_ᜀ();
      }
    }
```

So we can see here that it is establishing a string with the value `NeEd_MoRe_Bawlz`, taking the current hour from the system time, and a string `strB` which will store the output, and passing them as arguments to the `this.eval_ᜀ` function. In addition to that it takes our input (which is stored in the textbox from the form) and storing it in the string variable `text`. Later on we see that it compares the `text` variable against the output of the `this.eval_ᜀ` function stored in the `strB` variable. We can see that if they aren't even then it runs a function which prints error messages that we get when we submit random text, so we probably need to have the strings be even in order to solve the challenge (also the object `Sorry You Suck` is a victory picture). Let's take a look at the function which outputs to `strB`:

```
    private void eval_ᜀ(string _param1, int _param2, ref string _param3)
    {
      int index = 0;
      if (0 < param0.Length)
      {
        do
        {
          char ch = param0[index];
          int num = 1;
          if (1 < param1)
          {
            do
            {
              ch = Convert.ToChar(this.eval_ᜀ(Convert.ToInt32(ch), num));
              ++num;
            }
            while (num < param1);
          }
          param2 += (string) (object) ch;
          ++index;
        }
        while (index < param0.Length);
      }
      param2 = this.eval_ᜀ(param2);
    }
```

So we can see here that the three parameters it gets are param0 (the `NeEd_MoRe_Bawlz` string), param1 (the current hour), and param2 (the output string). I know that it appears to import param 1-3, however if we look at the other functions it appears that for importing parameters the count starts at 1, however when it uses it the count starts at 0 so there is a difference of 1.

Looking at what it actually does, we see that it essentially will loop through the function for each character in `NeEd_MoRe_Bawlz`, then writes the output of it, ran through a seperate function. to param2. Looking at what happens each iteration of the first while loop, it appears that another while loop will run another while loop that runs for as many times equal to the current hour. In that loop it will take the current character, and the iteration continues, and feed into another function, then write the output to the current character. After that while loop, it will add it to the output string. Then it finished by passing the value of the output string to another function, then taking its output and writing it to the output string. Let's take a look at the first function:

```
    private int eval_ᜀ(int _param1, int _param2)
    {
      return new int[30]
      {
        2,
        3,
        5,
        7,
        11,
        13,
        17,
        19,
        23,
        29,
        31,
        37,
        41,
        43,
        47,
        53,
        59,
        61,
        67,
        71,
        73,
        79,
        83,
        89,
        97,
        101,
        103,
        107,
        109,
        113
      }[param1] ^ param0;
    }
```

So we can see that it establishes an integer array, then xors the current_character with whatever object has an index that is equivalent to the iteration count of the while loop that is in. Let's take a look at the other function:

```
    private string eval_ᜀ(string _param1)
    {
      return BitConverter.ToString(new MD5CryptoServiceProvider().ComputeHash(Encoding.ASCII.GetBytes(param0))).Replace("-", "");
    }
```

We can see that this just essentially creates an MD5 hash of the input. So to figure out the string that is needed to, we can just recreate the xor function and then just take the MD5 hash of the output. To deal with the hour, we can just run it 24 times so we will have a hash for every possible value. Here is the python code for it:

```
# Import hashlib
import hashlib

# Esablish the integer array which will be used for xpromg
x0 = [ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113]

#Define the function which will tun the first loop
def enc(inp):
    #Establish the length of the input, and the for loop to run 24 times
    len_inp = len(inp)
    for i in range(1, 25):
        #Pass the input to the xor function, and print the output
        out = ""
        c = inp
        out = xor(c, i)
        print out


def xor(inp, c):
    # Establish the output string, and the first for loop which will run for the length of the input
    output = ""
    for i in xrange(len(inp)):
        current_character = inp[i]
        # Run the second for loop, which will run as many times equal to the current hour, and xor the input against the int array
        for j in range(1, c):
            current_character = chr(x0[j] ^ ord(current_character))            
        # Add the output of the previous for loop to the output string
        output += current_character
    #Hash and return the output
    hash = hashlib.md5()
    hash.update(output)
    output = hash.hexdigest()
    return output

# Establish the string "NeEd_MoRe_Bawlz" and run the enc function
enc_input = "NeEd_MoRe_Bawlz"
enc(enc_input)
```

When we run it:

```
$    python solve.py
cfdf804ce0c601f97c3dc7c2026e44fd
d96090e563ea15b7c440684727b0fecf
8fd9b04487552379d6c48cef0d63cc82
f9a66fa6113821d352bebfaa6a7f1977
88a4c0cfa9e937d3d16a5d51f3ecd8b3
c2a0150a72390a2263964f07b88a13b1
ca88f85fdba05e5cb6307b93a1dc727f
5de1575b8e12b0d2eabb773bbfa10701
784c334c79a378fd62b0e156247c97b6
269d731cd5180a91ed6edda26dfe4c28
095b965fe1f52d30464ad0ce099f9b5f
bebf06d90d6f9652476d244470c66bec
10a9c866379106bc43b138e16cd58ba2
91d69e2c6e97f98d4ee096590e978a2d
6dbf3a8df194bf573f46086c9acd3828
aef0cbdcd943997e7bca5dd711e6f580
ca88f85fdba05e5cb6307b93a1dc727f
e139dc68a502e59913af688af225e2a2
374a03db139b5a43a21377d9410b34d7
83ff9d84ce21b77f217637d16e519b4f
bdc511d175460bafb2d1930d5155753f
18ddd65bc857a2332841521a3c83de5e
8436d9b870f35ada28918a00fbde944e
8bf731eed0da5507004f831477a48241
```

When we go ahead and try all of the outputs (or you could just pick the one that matches your input if you don’t want to brute force it), we find that one of them works and we get the flag `key(0920303251BABE89911ECEAD17FEBF30)`.


