library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity neorv32_secure_boot_rsa is
  generic (
    RSA_KEY_SIZE : integer := 2048
  );
  port (
    clk_i      : in std_ulogic; -- global clock line
    rstn_i     : in std_ulogic; -- async reset, low-active
    start_i    : in std_ulogic; -- start signal
    base_i     : in std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0); -- base of the modular exponentiation
    exponent_i : in std_ulogic_vector(19 downto 0); -- exponent of the modular exponentiation
    modulus_i  : in std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0); -- modulus of the modular exponentiation
    result_o   : out std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0); -- result of the modular exponentiation
    done_o     : out std_ulogic -- done signal
  );
end neorv32_secure_boot_rsa;

architecture neorv32_secure_boot_rsa_rtl of neorv32_secure_boot_rsa is

  component neorv32_secure_boot_mod_mult is
    generic (
      RSA_KEY_SIZE : integer := RSA_KEY_SIZE
    );
    port (
      clk_i    : in std_ulogic;
      rst_i    : in std_ulogic;
      a_i      : in std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0);
      b_i      : in std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0);
      n_i      : in std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0);
      start_i  : in std_ulogic;
      result_o : out std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0);
      done_o   : out std_ulogic
    );
  end component;

  type state_t is (
    IDLE,
    LOAD,
    CHECK_EXP,
    MULTIPLY_START,
    MULTIPLY_WAIT,
    SQUARE_START,
    SQUARE_WAIT,
    UPDATE_EXP,
    DONE_STATE
  );
  signal current_state, next_state : state_t;

  signal base_reg           : std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0);
  signal exponent_index_reg : integer range 0 to 20;
  signal result_reg         : std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0);

  signal mod_mult_start_reg, mod_mult_done_wire : std_ulogic;
  signal mod_mult_result_wire                   : std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0);
  signal mod_mult_a_in_wire, mod_mult_b_in_wire : std_ulogic_vector(RSA_KEY_SIZE - 1 downto 0);
  signal rst_signal_wire                        : std_ulogic;

begin

  rst_signal_wire <= '1' when rstn_i = '0' else
    '0';

  -- Structural MUX for mod_mult inputs
  mod_mult_a_in_wire <= result_reg when (current_state = MULTIPLY_START or current_state = MULTIPLY_WAIT) else
    base_reg;
  mod_mult_b_in_wire <= base_reg;

  mod_mult_inst : neorv32_secure_boot_mod_mult
  generic map(
    RSA_KEY_SIZE => RSA_KEY_SIZE
  )
  port map
  (
    clk_i    => clk_i,
    rst_i    => rst_signal_wire,
    a_i      => mod_mult_a_in_wire,
    b_i      => mod_mult_b_in_wire,
    n_i      => modulus_i,
    start_i  => mod_mult_start_reg,
    result_o => mod_mult_result_wire,
    done_o   => mod_mult_done_wire
  );

  -- FSM state transition logic (combinatorial)
  process (current_state, start_i, exponent_index_reg, exponent_i, mod_mult_done_wire)
  begin
    next_state <= current_state;
    case current_state is
      when IDLE =>
        if start_i = '1' then
          next_state <= LOAD;
        end if;
      when LOAD =>
        next_state <= CHECK_EXP;
      when CHECK_EXP =>
        if exponent_index_reg = 20 then
          next_state <= DONE_STATE;
        elsif exponent_i(exponent_index_reg) = '1' then
          next_state <= MULTIPLY_START;
        else
          next_state <= SQUARE_START;
        end if;
      when MULTIPLY_START =>
        next_state <= MULTIPLY_WAIT;
      when MULTIPLY_WAIT =>
        if mod_mult_done_wire = '1' then
          next_state <= SQUARE_START;
        end if;
      when SQUARE_START =>
        next_state <= SQUARE_WAIT;
      when SQUARE_WAIT =>
        if mod_mult_done_wire = '1' then
          next_state <= UPDATE_EXP;
        end if;
      when UPDATE_EXP =>
        next_state <= CHECK_EXP;
      when DONE_STATE =>
        next_state <= IDLE;
    end case;
  end process;

  -- FSM and Datapath Update Logic (clocked)
  process (clk_i, rstn_i)
  begin
    if rstn_i = '0' then
      current_state      <= IDLE;
      base_reg           <= (others => '0');
      exponent_index_reg <= 0;
      result_reg         <= (others => '0');
      done_o             <= '0';
      mod_mult_start_reg <= '0';
    elsif rising_edge(clk_i) then
      current_state      <= next_state;
      done_o             <= '0';
      mod_mult_start_reg <= '0';

      case current_state is
        when IDLE =>
          done_o             <= '0';
          mod_mult_start_reg <= '0';
        when LOAD =>
          base_reg           <= base_i;
          exponent_index_reg <= 0;
          result_reg         <= std_ulogic_vector(to_unsigned(1, RSA_KEY_SIZE));
          mod_mult_start_reg <= '0';
        when CHECK_EXP =>
          -- No datapath change
        when MULTIPLY_START =>
          mod_mult_start_reg <= '1';
        when MULTIPLY_WAIT =>
          if mod_mult_done_wire = '1' then
            result_reg <= mod_mult_result_wire;
          end if;
        when SQUARE_START =>
          mod_mult_start_reg <= '1';
        when SQUARE_WAIT =>
          if mod_mult_done_wire = '1' then
            base_reg <= mod_mult_result_wire;
          end if;
        when UPDATE_EXP =>
          exponent_index_reg <= exponent_index_reg + 1;
        when DONE_STATE =>
          done_o <= '1';
      end case;
    end if;
  end process;

  result_o <= result_reg;

end neorv32_secure_boot_rsa_rtl;
