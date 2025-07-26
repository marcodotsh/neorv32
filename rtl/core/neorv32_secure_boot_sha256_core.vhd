--MIT License
--
--Copyright (c) 2017  Danny Savory
--
--Permission is hereby granted, free of charge, to any person obtaining a copy
--of this software and associated documentation files (the "Software"), to deal
--in the Software without restriction, including without limitation the rights
--to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
--copies of the Software, and to permit persons to whom the Software is
--furnished to do so, subject to the following conditions:
--
--The above copyright notice and this permission notice shall be included in all
--copies or substantial portions of the Software.
--
--THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY, EXPRESS OR
--IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
--FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
--AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
--LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
--OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
--SOFTWARE.
-- ############################################################################
--  The official specifications of the SHA-256 algorithm can be found here:
--      http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
-- ##################################################################
--     This SHA_256_CORE module reads in PADDED message blocks (from
--      an external source) and hashes the resulting message
-- ##################################################################

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
library neorv32;
use neorv32.neorv32_secure_boot_sha256_package.all;

entity neorv32_secure_boot_sha256_core is
  generic (
    RESET_VALUE : std_ulogic := '0' --reset enable value
  );
  port (
    clk_i           : in std_ulogic; -- global clock line
    rst_i           : in std_ulogic; -- async reset, see RESET_VALUE for polarity
    block_waiting_o : out std_ulogic; -- core raises this when it is waiting for a new block to process
    block_valid_i   : in std_ulogic; -- testbench raises this to indicate a new block is ready
    block_process_o : out std_ulogic; -- core raises this when it is processing a block
    n_blocks_i      : in std_ulogic_vector(31 downto 0); --N, the number of (padded) message blocks
    msg_block_i     : in std_ulogic_vector(0 to (16 * WORD_SIZE) - 1); -- the message block to process
    done_o          : out std_ulogic; -- done signal
    data_o          : out std_ulogic_vector((WORD_SIZE * 8) - 1 downto 0) --SHA-256 results in a 256-bit hash value
  );
end entity;

architecture neorv32_secure_boot_sha256_core_rtl of neorv32_secure_boot_sha256_core is
  signal hash_round_counter_reg : natural               := 0;
  signal hash_02_counter_reg    : integer range 0 to 64 := 0;

  --Temporary words
  signal T1 : std_ulogic_vector(WORD_SIZE - 1 downto 0) := (others => '0');
  signal T2 : std_ulogic_vector(WORD_SIZE - 1 downto 0) := (others => '0');

  --Working variables, 8 32-bit words
  signal a : std_ulogic_vector(WORD_SIZE - 1 downto 0) := (others => '0');
  signal b : std_ulogic_vector(WORD_SIZE - 1 downto 0) := (others => '0');
  signal c : std_ulogic_vector(WORD_SIZE - 1 downto 0) := (others => '0');
  signal d : std_ulogic_vector(WORD_SIZE - 1 downto 0) := (others => '0');
  signal e : std_ulogic_vector(WORD_SIZE - 1 downto 0) := (others => '0');
  signal f : std_ulogic_vector(WORD_SIZE - 1 downto 0) := (others => '0');
  signal g : std_ulogic_vector(WORD_SIZE - 1 downto 0) := (others => '0');
  signal h : std_ulogic_vector(WORD_SIZE - 1 downto 0) := (others => '0');

  constant K : K_DATA := (
  --address 0
  X"428a2f98", X"71374491", X"b5c0fbcf", X"e9b5dba5",
  X"3956c25b", X"59f111f1", X"923f82a4", X"ab1c5ed5",
  X"d807aa98", X"12835b01", X"243185be", X"550c7dc3",
  X"72be5d74", X"80deb1fe", X"9bdc06a7", X"c19bf174",
  X"e49b69c1", X"efbe4786", X"0fc19dc6", X"240ca1cc",
  X"2de92c6f", X"4a7484aa", X"5cb0a9dc", X"76f988da",
  X"983e5152", X"a831c66d", X"b00327c8", X"bf597fc7",
  X"c6e00bf3", X"d5a79147", X"06ca6351", X"14292967",
  X"27b70a85", X"2e1b2138", X"4d2c6dfc", X"53380d13",
  X"650a7354", X"766a0abb", X"81c2c92e", X"92722c85",
  X"a2bfe8a1", X"a81a664b", X"c24b8b70", X"c76c51a3",
  X"d192e819", X"d6990624", X"f40e3585", X"106aa070",
  X"19a4c116", X"1e376c08", X"2748774c", X"34b0bcb5",
  X"391c0cb3", X"4ed8aa4a", X"5b9cca4f", X"682e6ff3",
  X"748f82ee", X"78a5636f", X"84c87814", X"8cc70208",
  X"90befffa", X"a4506ceb", X"bef9a3f7", X"c67178f2"
  );

  -- Area-optimized message schedule (16-word circular buffer)
  signal W         : M_DATA;
  signal w_temp    : std_ulogic_vector(WORD_SIZE - 1 downto 0);
  signal w_current : std_ulogic_vector(WORD_SIZE - 1 downto 0);

  --Hash values w/ initial hash values; 8 32-bit words
  signal HV                  : H_DATA;
  constant HV_INITIAL_VALUES : H_DATA := (X"6a09e667", X"bb67ae85", X"3c6ef372",
  X"a54ff53a", X"510e527f", X"9b05688c",
  X"1f83d9ab", X"5be0cd19");
  --intermediate Message block values; for use with a for-generate loop;
  signal M_INT : M_DATA;

  type SHA_256_HASH_CORE_STATE is (RESET, IDLE, WAIT_BLOCK, READ_MSG_BLOCK, HASH_01, HASH_02, HASH_02b, HASH_03, DONE);
  signal CURRENT_STATE, NEXT_STATE : SHA_256_HASH_CORE_STATE;
begin
  --current state logic
  process (clk_i, rst_i)
  begin
    if (rst_i = RESET_VALUE) then
      CURRENT_STATE <= RESET;
    elsif (clk_i'event and clk_i = '1') then
      CURRENT_STATE <= NEXT_STATE;
    end if;
  end process;
  --next state logic
  process (CURRENT_STATE, rst_i, n_blocks_i, hash_round_counter_reg, hash_02_counter_reg, block_valid_i)
  begin
    case CURRENT_STATE is
      when RESET =>
        if (rst_i = RESET_VALUE) then
          NEXT_STATE <= RESET;
        else
          NEXT_STATE <= IDLE;
        end if;
      when IDLE =>
        NEXT_STATE <= WAIT_BLOCK;
      when WAIT_BLOCK =>
        if (block_valid_i = '1') then
          NEXT_STATE <= READ_MSG_BLOCK;
        else
          NEXT_STATE <= WAIT_BLOCK;
        end if;
      when READ_MSG_BLOCK =>
        NEXT_STATE <= HASH_01;
      when HASH_01 =>
        NEXT_STATE <= HASH_02;
      when HASH_02 =>
        if (hash_02_counter_reg = 64) then
          NEXT_STATE <= HASH_03;
        else
          NEXT_STATE <= HASH_02b;
        end if;
      when HASH_02b =>
        NEXT_STATE <= HASH_02;
      when HASH_03 =>
        if (hash_round_counter_reg = unsigned(n_blocks_i) - 1) then
          NEXT_STATE <= DONE;
        else
          NEXT_STATE <= WAIT_BLOCK;
        end if;
      when DONE =>
        NEXT_STATE <= DONE; --stay in done state unless reset
    end case;
  end process;

  -- Combinatorial logic for w_temp
  w_temp    <= std_ulogic_vector(unsigned(SIGMA_LCASE_1(W(14))) + unsigned(W(9)) + unsigned(SIGMA_LCASE_0(W(1))) + unsigned(W(0)));
  w_current <= w_temp when hash_02_counter_reg >= 16 else
    W(hash_02_counter_reg);

  process (clk_i, rst_i)
  begin
    if (rst_i = RESET_VALUE) then
      hash_round_counter_reg <= 0;
      a                      <= (others => '0');
      b                      <= (others => '0');
      c                      <= (others => '0');
      d                      <= (others => '0');
      e                      <= (others => '0');
      f                      <= (others => '0');
      g                      <= (others => '0');
      h                      <= (others => '0');
      T1                     <= (others => '0');
      T2                     <= (others => '0');
      W                      <= (others => (others => '0'));
      HV                     <= HV_INITIAL_VALUES;
      hash_02_counter_reg    <= 0;
    elsif (clk_i'event and clk_i = '1') then
      case CURRENT_STATE is
        when RESET =>
          HV                     <= HV_INITIAL_VALUES;
          hash_02_counter_reg    <= 0;
          hash_round_counter_reg <= 0;
        when IDLE           =>
        when WAIT_BLOCK     =>
        when READ_MSG_BLOCK =>
          if (hash_round_counter_reg = 0) then
            HV <= HV_INITIAL_VALUES;
          end if;
          W <= M_INT;
        when HASH_01 =>
          a <= HV(0);
          b <= HV(1);
          c <= HV(2);
          d <= HV(3);
          e <= HV(4);
          f <= HV(5);
          g <= HV(6);
          h <= HV(7);
        when HASH_02 =>
          if (hash_02_counter_reg /= 64) then
            T1 <= std_ulogic_vector(unsigned(h) + unsigned(SIGMA_UCASE_1(e)) + unsigned(CH(e, f, g)) + unsigned(K(hash_02_counter_reg)) + unsigned(w_current));
            T2 <= std_ulogic_vector(unsigned(SIGMA_UCASE_0(a)) + unsigned(MAJ(a, b, c)));
          else
            hash_02_counter_reg <= 0;
          end if;
        when HASH_02b =>
          h <= g;
          g <= f;
          f <= e;
          e <= std_ulogic_vector(unsigned(d) + unsigned(T1));
          d <= c;
          c <= b;
          b <= a;
          a <= std_ulogic_vector(unsigned(T1) + unsigned(T2));

          if (hash_02_counter_reg >= 16) then
            -- shift the by 1 the message schedule 32-bit words
            W(0 to 14) <= W(1 to 15);
            W(15)      <= w_temp;
          end if;
          hash_02_counter_reg <= hash_02_counter_reg + 1;
        when HASH_03 =>
          HV(0) <= std_ulogic_vector(unsigned(a) + unsigned(HV(0)));
          HV(1) <= std_ulogic_vector(unsigned(b) + unsigned(HV(1)));
          HV(2) <= std_ulogic_vector(unsigned(c) + unsigned(HV(2)));
          HV(3) <= std_ulogic_vector(unsigned(d) + unsigned(HV(3)));
          HV(4) <= std_ulogic_vector(unsigned(e) + unsigned(HV(4)));
          HV(5) <= std_ulogic_vector(unsigned(f) + unsigned(HV(5)));
          HV(6) <= std_ulogic_vector(unsigned(g) + unsigned(HV(6)));
          HV(7) <= std_ulogic_vector(unsigned(h) + unsigned(HV(7)));
          if (hash_round_counter_reg = unsigned(n_blocks_i) - 1) then
            hash_round_counter_reg <= 0;
          else
            hash_round_counter_reg <= hash_round_counter_reg + 1;
          end if;
        when DONE =>
      end case;
    end if;
  end process;
  MESSAGE_BLOCK_INTERMEDIATE :
  for i in 0 to 15 generate
  begin
    M_INT(i) <= msg_block_i((WORD_SIZE * i) to WORD_SIZE * (i + 1) - 1);
  end generate;

  -- Block being processed signal (VHDL-93 compatible)
  block_process_o <=
    '1' when CURRENT_STATE = HASH_01 or
    CURRENT_STATE = HASH_02 or
    CURRENT_STATE = HASH_02b or
    CURRENT_STATE = HASH_03
    else
    '0';

  -- Waiting for a new block signal
  block_waiting_o <= '1' when CURRENT_STATE = WAIT_BLOCK else
    '0';

  -- FINISHED signal asserts when hashing is done
  done_o <= '1' when CURRENT_STATE = DONE else
    '0';
  data_o <= HV(0) & HV(1) & HV(2) & HV(3) & HV(4) & HV(5) & HV(6) & HV(7);
end architecture;
