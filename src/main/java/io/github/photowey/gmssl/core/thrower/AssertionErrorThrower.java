package io.github.photowey.gmssl.core.thrower;

/**
 * {@code AssertionErrorThrower}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/07
 */
public final class AssertionErrorThrower {

    private AssertionErrorThrower() {
        throwz(AssertionErrorThrower.class);
    }

    /**
     * throw {@link AssertionError} Error.
     */
    public static <T> void throwz(Class<T> clazz) {
        throw new AssertionError("No " + clazz.getName() + " instances for you!");
    }
}
