library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity neorv32_secure_boot_mod_mult is
  generic (
    RSA_KEY_SIZE : integer := 2048
  );
  port (
    clk_i    : in std_ulogic; -- global clock line
    rst_i    : in std_ulogic; -- async reset
    a_i      : in std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0); -- first operand of modular multiplication
    b_i      : in std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0); -- second operand of modular multiplication
    n_i      : in std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0); -- modulus of modular multiplication
    start_i  : in std_ulogic; -- start signal
    result_o : out std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0); -- operation result
    done_o   : out std_ulogic -- done signal
  );
end neorv32_secure_boot_mod_mult;

architecture neorv32_secure_boot_mod_mult_rtl of neorv32_secure_boot_mod_mult is

  component neorv32_secure_boot_serial_adder is
    generic (
      WIDTH      : integer := RSA_KEY_SIZE + 2;
      CHUNK_SIZE : integer := 9
    );
    port (
      clk_i     : in std_ulogic;
      rst_i     : in std_ulogic;
      start_i   : in std_ulogic;
      add_sub_i : in std_ulogic;
      a_i, b_i  : in std_ulogic_vector(WIDTH - 1 downto 0);
      s_o       : out std_ulogic_vector(WIDTH - 1 downto 0);
      done_o    : out std_ulogic
    );
  end component;

  constant ADDER_WIDTH : integer := RSA_KEY_SIZE + 2;

  type state_t is (
    IDLE,
    LOAD,
    LOOP_START,
    ADD_A_START, ADD_A_WAIT,
    SUB_N1_START, SUB_N1_WAIT,
    SUB_N2_START, SUB_N2_WAIT,
    LOOP_END,
    DONE_STATE
  );
  signal state : state_t := IDLE;

  signal result_reg : unsigned(ADDER_WIDTH - 1 downto 0);
  signal index_reg  : integer range 0 to RSA_KEY_SIZE - 1 := RSA_KEY_SIZE - 1;

  signal adder_b_wire                     : std_ulogic_vector(ADDER_WIDTH - 1 downto 0);
  signal adder_s_wire                     : std_ulogic_vector(ADDER_WIDTH - 1 downto 0);
  signal adder_start_reg, adder_done_wire : std_ulogic;
  signal adder_add_sub_reg                : std_ulogic;

begin

  adder_b_wire <= std_ulogic_vector(resize(unsigned(a_i), ADDER_WIDTH)) when state = ADD_A_START or state = ADD_A_WAIT else
    std_ulogic_vector(resize(unsigned(n_i), ADDER_WIDTH));

  serial_adder_inst : neorv32_secure_boot_serial_adder
  generic map(
    WIDTH => ADDER_WIDTH
  )
  port map
  (
    clk_i     => clk_i,
    rst_i     => rst_i,
    start_i   => adder_start_reg,
    add_sub_i => adder_add_sub_reg,
    a_i       => std_ulogic_vector(result_reg),
    b_i       => adder_b_wire,
    s_o       => adder_s_wire,
    done_o    => adder_done_wire
  );

  process (clk_i, rst_i)
  begin
    if rst_i = '1' then
      state             <= IDLE;
      index_reg         <= RSA_KEY_SIZE - 1;
      result_reg        <= (others => '0');
      adder_start_reg   <= '0';
      adder_add_sub_reg <= '0';
    elsif rising_edge(clk_i) then
      adder_start_reg <= '0';

      case state is
        when IDLE =>
          if start_i = '1' then
            state <= LOAD;
          end if;

        when LOAD             =>
          result_reg <= (others => '0');
          index_reg  <= RSA_KEY_SIZE - 1;
          state      <= LOOP_START;

        when LOOP_START =>
          result_reg <= result_reg sll 1;
          if b_i(index_reg) = '1' then
            state <= ADD_A_START;
          else
            state <= SUB_N2_START;
          end if;

        when ADD_A_START =>
          adder_add_sub_reg <= '0'; -- ADD
          adder_start_reg   <= '1';
          state             <= ADD_A_WAIT;

        when ADD_A_WAIT =>
          if adder_done_wire = '1' then
            result_reg <= unsigned(adder_s_wire);
            state      <= SUB_N1_START;
          end if;

        when SUB_N1_START =>
          adder_add_sub_reg <= '1'; -- SUB
          adder_start_reg   <= '1';
          state             <= SUB_N1_WAIT;

        when SUB_N1_WAIT =>
          if adder_done_wire = '1' then
            if adder_s_wire(ADDER_WIDTH - 1) = '0' then -- if result is not negative
              result_reg <= unsigned(adder_s_wire);
            end if;
            state <= SUB_N2_START;
          end if;

        when SUB_N2_START =>
          adder_add_sub_reg <= '1'; -- SUB
          adder_start_reg   <= '1';
          state             <= SUB_N2_WAIT;

        when SUB_N2_WAIT =>
          if adder_done_wire = '1' then
            if adder_s_wire(ADDER_WIDTH - 1) = '0' then -- if result is not negative
              result_reg <= unsigned(adder_s_wire);
            end if;
            state <= LOOP_END;
          end if;

        when LOOP_END =>
          if index_reg = 0 then
            state <= DONE_STATE;
          else
            index_reg <= index_reg - 1;
            state     <= LOOP_START;
          end if;

        when DONE_STATE =>
          state <= IDLE;
      end case;
    end if;
  end process;

  result_o <= std_ulogic_vector(result_reg(RSA_KEY_SIZE - 1 downto 0));
  done_o   <= '1' when state = DONE_STATE else
    '0';

end neorv32_secure_boot_mod_mult_rtl;
