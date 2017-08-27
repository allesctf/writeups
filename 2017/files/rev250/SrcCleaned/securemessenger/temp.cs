 public static byte[] encryptBlock(byte[] block, byte[,] matrix)
        {
            int i = 0;

            while (true)
            {
                if (!(i < block.Length))
                    return block;

                var b1 = block[i];
                var b2 = block[i + 1];

                byte b1_x = 0;
                byte b1_y = 0;
                byte b2_x = 0;
                byte b2_y = 0;

                byte x = 0;
                byte y = 0;

                while (y < 16)
                {
                    x = 0;
                    while (x < 16)
                    {
                        if (matrix[y,x] == b1)
                        {
                            b1_x = x;
                            b1_y = y;
                        }
                        else
                        {
                            if (matrix[y,x] == b2)
                            {
                                b2_x = x;
                                b2_y = y;
                            }
                        }
                        x += 1;
                    }
                    y += 1;
                }

                if (b1_x == b2_x && b1_y == b2_y)
                {
                    
                }
                else
                {
                    if (b1_y == b2_y)
                    {
                        b1_x += 1;
                        b2_x += 1;

                        if (b1_x >= 16) b1_x = 0;
                        if (b2_x >= 16) b2_x = 0;
                    }
                    else
                    {
                        byte tmp = b1_x;
                        b1_x = b2_x;
                        b2_x = tmp;
                    }
                }

                block[i] = matrix[b1_y,b1_x];
                block[i + 1] = matrix[b2_y,b2_x];

                i += 2;
            }
        }